// Package upstream — исходящие подключения Tor (и встроенных транспортов) через
// один или несколько вышестоящих прокси с автоматическим перебором.
// Поддерживаются: прямое подключение (direct), SOCKS5 и HTTP CONNECT, с авторизацией.
package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/merankanika/tor-connect/internal/socks5"
)

// Spec описывает один вариант выхода.
type Spec struct {
	Kind string // "direct", "socks5", "http"
	Addr string // host:port прокси (пусто для direct)
	User string
	Pass string
}

func (s Spec) String() string {
	if s.Kind == "direct" {
		return "direct"
	}
	if s.User != "" {
		return s.Kind + "://" + s.User + ":***@" + s.Addr
	}
	return s.Kind + "://" + s.Addr
}

// ParseSpec разбирает «direct», «socks5://[user:pass@]host:port», «socks5h://…», «http://[user:pass@]host:port».
func ParseSpec(raw string) (Spec, error) {
	raw = strings.TrimSpace(raw)
	if strings.EqualFold(raw, "direct") {
		return Spec{Kind: "direct"}, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Spec{}, fmt.Errorf("неверный адрес прокси %q (ожидается direct, socks5://… или http://…)", raw)
	}
	var kind string
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		kind = "socks5"
	case "http", "https":
		kind = "http"
	default:
		return Spec{}, fmt.Errorf("неподдерживаемый тип прокси %q", u.Scheme)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		if kind == "socks5" {
			port = "1080"
		} else {
			port = "8080"
		}
	}
	s := Spec{Kind: kind, Addr: net.JoinHostPort(host, port)}
	if u.User != nil {
		s.User = u.User.Username()
		s.Pass, _ = u.User.Password()
	}
	return s, nil
}

// ParseSpecs разбирает список адресов.
func ParseSpecs(list []string) ([]Spec, error) {
	out := make([]Spec, 0, len(list))
	for _, r := range list {
		s, err := ParseSpec(r)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Options — настройки перебора.
type Options struct {
	AttemptTimeout time.Duration // на одну попытку (по умолчанию 8 с)
	Cooldown       time.Duration // сколько неудачный вариант пробуется в последнюю очередь (по умолчанию 30 с)
	Logf           func(format string, args ...any)
	// DialDirect позволяет подменить прямое подключение (для тестов).
	DialDirect func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Dialer перебирает варианты выхода.
type Dialer struct {
	specs []Spec
	opt   Options

	mu       sync.Mutex
	last     int // индекс последнего успешного варианта, -1 если нет
	failedAt []time.Time
}

// New создаёт Dialer. Пустой список означает только прямое подключение.
func New(specs []Spec, opt Options) *Dialer {
	if len(specs) == 0 {
		specs = []Spec{{Kind: "direct"}}
	}
	if opt.AttemptTimeout <= 0 {
		opt.AttemptTimeout = 8 * time.Second
	}
	if opt.Cooldown <= 0 {
		opt.Cooldown = 30 * time.Second
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	if opt.DialDirect == nil {
		var d net.Dialer
		opt.DialDirect = d.DialContext
	}
	return &Dialer{specs: specs, opt: opt, last: -1, failedAt: make([]time.Time, len(specs))}
}

// order: сначала последний удачный, затем остальные по порядку конфигурации;
// недавно сбойные — в конец.
func (d *Dialer) order() []int {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	var good, bad []int
	add := func(i int) {
		if !d.failedAt[i].IsZero() && now.Sub(d.failedAt[i]) < d.opt.Cooldown {
			bad = append(bad, i)
		} else {
			good = append(good, i)
		}
	}
	if d.last >= 0 {
		add(d.last)
	}
	for i := range d.specs {
		if i != d.last {
			add(i)
		}
	}
	return append(good, bad...)
}

// DialContext подключается к addr, перебирая варианты выхода.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("upstream: сеть %q не поддерживается", network)
	}
	var errs []error
	for _, i := range d.order() {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		c, err := d.dialOne(ctx, d.specs[i], network, addr)
		if err == nil {
			d.mu.Lock()
			if d.last != i {
				d.opt.Logf("upstream: выход через %s", d.specs[i])
			}
			d.last = i
			d.failedAt[i] = time.Time{}
			d.mu.Unlock()
			return c, nil
		}
		d.mu.Lock()
		d.failedAt[i] = time.Now()
		d.mu.Unlock()
		d.opt.Logf("upstream: %s не сработал для %s: %v", d.specs[i], addr, err)
		errs = append(errs, fmt.Errorf("%s: %w", d.specs[i], err))
	}
	return nil, fmt.Errorf("upstream: ни один вариант выхода не сработал для %s: %w", addr, errors.Join(errs...))
}

func (d *Dialer) dialOne(parent context.Context, s Spec, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, d.opt.AttemptTimeout)
	defer cancel()
	if s.Kind == "direct" {
		return d.opt.DialDirect(ctx, network, addr)
	}
	var nd net.Dialer
	c, err := nd.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	_ = c.SetDeadline(deadline)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		c.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		c.Close()
		return nil, err
	}
	switch s.Kind {
	case "socks5":
		err = socks5.ClientHandshake(c, host, port, s.User, s.Pass)
	case "http":
		c, err = httpConnect(c, addr, s.User, s.Pass)
	default:
		err = fmt.Errorf("неизвестный тип %q", s.Kind)
	}
	if err != nil {
		if c != nil {
			c.Close()
		}
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func httpConnect(c net.Conn, addr, user, pass string) (net.Conn, error) {
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if user != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n"
	}
	req += "\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return c, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		return c, err
	}
	if resp.StatusCode != 200 {
		return c, fmt.Errorf("http-прокси ответил: %s", resp.Status)
	}
	if br.Buffered() > 0 {
		return &bufConn{Conn: c, r: br}, nil
	}
	return c, nil
}
