// Package portmap — проброс портов (директивы MapPort и MapPortUDP).
// Правило слушает порт на этом устройстве и перенаправляет подключения на другой адрес:
// напрямую, через Tor или через вышестоящие прокси. Занятый порт не ломает программу: правило пропускается.
package portmap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rule — одно правило проброса.
type Rule struct {
	Proto  string // "tcp" или "udp"
	Listen string // host:port, где слушаем
	Target string // host:port, куда пересылаем
	Via    string // tor, direct или upstream (для UDP только direct)
}

// Key — уникальный ключ правила.
func (r Rule) Key() string { return r.Proto + "|" + r.Listen + "|" + r.Target + "|" + r.Via }

func (r Rule) String() string {
	return fmt.Sprintf("%s %s → %s (%s)", strings.ToUpper(r.Proto), r.Listen, r.Target, r.Via)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func normHostPort(s, defHost string) (string, error) {
	if isDigits(s) {
		s = net.JoinHostPort(defHost, s)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("неверный адрес %q (ожидается порт или хост:порт)", s)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("неверный порт в %q", s)
	}
	if host == "" {
		host = defHost
	}
	return net.JoinHostPort(host, port), nil
}

func isLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}

// ParseRule разбирает «[адрес:]порт to [хост:]порт [via tor|direct|upstream]».
// Только порт слева означает прослушивание на всех интерфейсах (0.0.0.0), только порт справа — локальный порт (127.0.0.1).
// Способ по умолчанию: для .onion — tor; для локальных и частных адресов — direct; для остальных — tor; для UDP — direct.
func ParseRule(proto, value string) (Rule, error) {
	f := strings.Fields(value)
	if len(f) < 3 || !strings.EqualFold(f[1], "to") {
		return Rule{}, errors.New("ожидается: [адрес:]порт to [хост:]порт [via tor|direct|upstream]")
	}
	listen, err := normHostPort(f[0], "0.0.0.0")
	if err != nil {
		return Rule{}, err
	}
	target, err := normHostPort(f[2], "127.0.0.1")
	if err != nil {
		return Rule{}, err
	}
	via := ""
	if len(f) > 3 {
		if len(f) != 5 || !strings.EqualFold(f[3], "via") {
			return Rule{}, errors.New("после адреса назначения допустимо только «via tor|direct|upstream»")
		}
		via = strings.ToLower(f[4])
	}
	host, _, _ := net.SplitHostPort(target)
	onion := strings.HasSuffix(strings.ToLower(host), ".onion")
	switch strings.ToLower(proto) {
	case "udp":
		if via != "" && via != "direct" {
			return Rule{}, errors.New("UDP не может идти через Tor или прокси: допустим только direct")
		}
		if onion {
			return Rule{}, errors.New("UDP не поддерживается для .onion")
		}
		via = "direct"
		proto = "udp"
	case "tcp":
		proto = "tcp"
		switch via {
		case "":
			if onion || !isLocalHost(host) {
				via = "tor"
			} else {
				via = "direct"
			}
		case "tor", "direct", "upstream":
		default:
			return Rule{}, fmt.Errorf("неизвестный способ %q (tor, direct или upstream)", via)
		}
		if onion && via != "tor" {
			return Rule{}, errors.New(".onion-адреса доступны только через Tor")
		}
	default:
		return Rule{}, fmt.Errorf("неизвестный протокол %q", proto)
	}
	return Rule{Proto: proto, Listen: listen, Target: target, Via: via}, nil
}

// Dialers — способы подключения к назначению.
type Dialers struct {
	Tor      func(ctx context.Context, host string, port int, isolation string) (net.Conn, error)
	Direct   func(ctx context.Context, network, addr string) (net.Conn, error)
	Upstream func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Manager запускает и останавливает слушатели по набору правил.
type Manager struct {
	d    Dialers
	logf func(format string, args ...any)

	mu      sync.Mutex
	running map[string]*instance
}

type instance struct {
	rule Rule
	stop func()
}

// NewManager создаёт менеджер.
func NewManager(d Dialers, logf func(string, ...any)) *Manager {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Manager{d: d, logf: logf, running: map[string]*instance{}}
}

// Apply приводит слушатели в соответствие с правилами: лишние останавливает, новые запускает.
// Правила с занятым портом пропускаются (с сообщением) и пробуются снова при следующем вызове.
// Возвращает число работающих правил и число пропущенных.
func (m *Manager) Apply(rules []Rule) (running, skipped int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]Rule{}
	var order []string
	for _, r := range rules {
		if _, dup := want[r.Key()]; !dup {
			want[r.Key()] = r
			order = append(order, r.Key())
		}
	}
	for k, in := range m.running {
		if _, ok := want[k]; !ok {
			in.stop()
			delete(m.running, k)
			m.logf("проброс остановлен: %s", in.rule)
		}
	}
	for _, k := range order {
		if _, ok := m.running[k]; ok {
			continue
		}
		r := want[k]
		var stop func()
		var err error
		if r.Proto == "udp" {
			stop, err = m.startUDP(r)
		} else {
			stop, err = m.startTCP(r)
		}
		if err != nil {
			skipped++
			m.logf("проброс пропущен (%s): %v", r, err)
			continue
		}
		m.running[k] = &instance{rule: r, stop: stop}
		m.logf("проброс запущен: %s", r)
	}
	return len(m.running), skipped
}

// Close останавливает все слушатели.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, in := range m.running {
		in.stop()
		delete(m.running, k)
	}
}

// ---- TCP ----

type connSet struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func (s *connSet) add(c net.Conn) {
	s.mu.Lock()
	if s.m == nil {
		s.m = map[net.Conn]struct{}{}
	}
	s.m[c] = struct{}{}
	s.mu.Unlock()
}

func (s *connSet) del(c net.Conn) {
	s.mu.Lock()
	delete(s.m, c)
	s.mu.Unlock()
}

func (s *connSet) closeAll() {
	s.mu.Lock()
	for c := range s.m {
		c.Close()
	}
	s.m = nil
	s.mu.Unlock()
}

func (m *Manager) dial(ctx context.Context, r Rule) (net.Conn, error) {
	host, portStr, _ := net.SplitHostPort(r.Target)
	port, _ := strconv.Atoi(portStr)
	switch r.Via {
	case "tor":
		if m.d.Tor == nil {
			return nil, errors.New("подключение через Tor недоступно")
		}
		return m.d.Tor(ctx, host, port, "portmap:"+r.Key())
	case "upstream":
		if m.d.Upstream == nil {
			return nil, errors.New("вышестоящие прокси недоступны")
		}
		return m.d.Upstream(ctx, "tcp", r.Target)
	default:
		if m.d.Direct == nil {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", r.Target)
		}
		return m.d.Direct(ctx, "tcp", r.Target)
	}
}

func (m *Manager) startTCP(r Rule) (func(), error) {
	ln, err := net.Listen("tcp", r.Listen)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	var conns connSet
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.add(c)
			go func() {
				defer conns.del(c)
				defer c.Close()
				dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
				up, err := m.dial(dctx, r)
				dcancel()
				if err != nil {
					m.logf("проброс %s: не удалось подключиться: %v", r, err)
					return
				}
				conns.add(up)
				defer conns.del(up)
				defer up.Close()
				pipe(c, up)
			}()
		}
	}()
	return func() { cancel(); ln.Close(); conns.closeAll() }, nil
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

// ---- UDP (только напрямую: Tor и onion-службы не переносят UDP) ----

type udpSession struct {
	up   net.Conn
	last time.Time
}

func (m *Manager) startUDP(r Rule) (func(), error) {
	pc, err := net.ListenPacket("udp", r.Listen)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	sessions := map[string]*udpSession{}

	go func() { // уборка простаивающих сеансов
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				mu.Lock()
				for k, s := range sessions {
					if time.Since(s.last) > 90*time.Second {
						s.up.Close()
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			key := addr.String()
			mu.Lock()
			s := sessions[key]
			if s == nil {
				dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
				var up net.Conn
				if m.d.Direct != nil {
					up, err = m.d.Direct(dctx, "udp", r.Target)
				} else {
					var d net.Dialer
					up, err = d.DialContext(dctx, "udp", r.Target)
				}
				dcancel()
				if err != nil {
					mu.Unlock()
					m.logf("проброс %s: не удалось открыть сокет: %v", r, err)
					continue
				}
				s = &udpSession{up: up}
				sessions[key] = s
				go func(client net.Addr, up net.Conn) {
					b := make([]byte, 65535)
					for {
						k, err := up.Read(b)
						if err != nil {
							return
						}
						mu.Lock()
						if cur := sessions[client.String()]; cur != nil {
							cur.last = time.Now()
						}
						mu.Unlock()
						if _, err := pc.WriteTo(b[:k], client); err != nil {
							return
						}
					}
				}(addr, up)
			}
			s.last = time.Now()
			up := s.up
			mu.Unlock()
			_, _ = up.Write(buf[:n])
		}
	}()
	return func() {
		cancel()
		pc.Close()
		mu.Lock()
		for k, s := range sessions {
			s.up.Close()
			delete(sessions, k)
		}
		mu.Unlock()
	}, nil
}
