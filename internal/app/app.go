// Package app связывает части tor-connect: разбор аргументов, поиск и создание tecon.cfg,
// генерацию torrc для Tor, локальный маршрутизатор вышестоящих прокси, подключение к управляющему
// порту Tor и применение изменений конфигурации «на лету». Пакет не зависит от cgo.
package app

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/merankanika/tor-connect/internal/tcontrol"
	"github.com/merankanika/tor-connect/internal/tecon"
	"github.com/merankanika/tor-connect/internal/upstream"
)

// Options — разобранные аргументы командной строки.
type Options struct {
	ConfigPath  string   // явный путь к файлу настроек (-f, -c, голое имя файла)
	Upstreams   []string // значения -upstream: заменяют строки Upstream из файла
	TorArgs     []string // остальные аргументы передаются Tor
	Passthrough bool     // --version/--help и т.п.: запустить Tor без конфигурации
}

var passthrough = map[string]bool{
	"--version": true, "-version": true, "--help": true, "-h": true, "-help": true,
	"--hash-password": true, "--list-torrc-options": true, "--list-deprecated-options": true,
}

func isConfigFlag(a string) bool {
	switch a {
	case "-f", "-c", "-config", "--config", "--torrc-file":
		return true
	}
	return false
}

// ParseArgs разбирает аргументы (без имени программы).
func ParseArgs(args []string) (Options, error) {
	var o Options
	for _, a := range args {
		if passthrough[strings.ToLower(a)] {
			o.Passthrough = true
			o.TorArgs = append([]string(nil), args...)
			return o, nil
		}
	}
	rest := args
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		o.ConfigPath = rest[0] // голое имя файла: tor-connect.exe мой.cfg
		rest = rest[1:]
	}
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case isConfigFlag(a):
			if i+1 >= len(rest) {
				return o, fmt.Errorf("после %s не указан файл", a)
			}
			o.ConfigPath = rest[i+1]
			i++
		case a == "-upstream" || a == "--upstream":
			if i+1 >= len(rest) {
				return o, fmt.Errorf("после %s не указан адрес прокси", a)
			}
			o.Upstreams = append(o.Upstreams, rest[i+1])
			i++
		default:
			o.TorArgs = append(o.TorArgs, a)
		}
	}
	return o, nil
}

// Session — подготовленный запуск.
type Session struct {
	ExeDir, Cwd string
	ConfigPath  string
	DataDir     string
	TorrcPath   string
	TorArgs     []string // полный argv для Tor (кроме argv[0])
	Notes       []string // сообщения о подготовке

	Cfg      *tecon.Config
	Dialer   *upstream.Dialer
	logf     func(format string, args ...any)
	cliUps   bool
	portFile string

	ln     net.Listener
	cancel context.CancelFunc

	mu       sync.Mutex
	ctl      *tcontrol.Client
	lastStat fileStat
	lastText string
}

type fileStat struct {
	mod  time.Time
	size int64
}

func q(p string) string { return `"` + filepath.ToSlash(p) + `"` }

// Prepare находит или создаёт файл настроек, разбирает его, запускает локальный маршрутизатор
// вышестоящих прокси и записывает torrc для Tor.
func Prepare(o Options, exeDir, cwd string, logf func(string, ...any)) (*Session, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	s := &Session{ExeDir: exeDir, Cwd: cwd, logf: logf, cliUps: len(o.Upstreams) > 0}

	// 1. Файл настроек.
	if o.ConfigPath != "" {
		p, err := filepath.Abs(o.ConfigPath)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := tecon.Write(p); err != nil {
				return nil, fmt.Errorf("не удалось создать %s: %w", p, err)
			}
			s.Notes = append(s.Notes, "создан файл настроек по умолчанию: "+p)
		}
		s.ConfigPath = p
	} else {
		p, notes := tecon.Find(exeDir, cwd)
		s.Notes = append(s.Notes, notes...)
		if p == "" {
			var err error
			if p, err = tecon.Create(exeDir, cwd); err != nil {
				return nil, err
			}
			s.Notes = append(s.Notes, "создан файл настроек по умолчанию: "+p)
		}
		s.ConfigPath = p
	}
	s.Notes = append(s.Notes, "файл настроек: "+s.ConfigPath)

	text, st, err := readConfig(s.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s: %w", s.ConfigPath, err)
	}
	cfg, err := tecon.Parse(text)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.ConfigPath, err)
	}
	s.Cfg, s.lastStat, s.lastText = cfg, st, text
	for _, w := range cfg.Warnings {
		s.Notes = append(s.Notes, "предупреждение: "+w)
	}

	// 2. Вышестоящие прокси и локальный маршрутизатор (Tor всегда ходит через него: список меняется на лету).
	raw := cfg.Upstreams
	if s.cliUps {
		raw = o.Upstreams
	}
	specs, err := upstream.ParseSpecs(raw)
	if err != nil {
		return nil, err
	}
	s.Dialer = upstream.New(specs, upstream.Options{Logf: logf})
	s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть локальный порт маршрутизатора: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() { _ = upstream.Serve(ctx, s.ln, s.Dialer) }()
	if len(specs) > 0 {
		s.Notes = append(s.Notes, "вышестоящие прокси по порядку: "+describe(specs))
	}

	// 3. Каталог данных и torrc для Tor.
	dd, ok := cfg.Value("DataDirectory")
	if !ok || dd == "" {
		dd = filepath.Join(exeDir, "data")
		s.Notes = append(s.Notes, "каталог данных (по умолчанию): "+dd)
	}
	if abs, err := filepath.Abs(dd); err == nil {
		dd = abs
	}
	if err := os.MkdirAll(dd, 0o700); err != nil {
		s.Close()
		return nil, fmt.Errorf("не удалось создать каталог данных %s: %w", dd, err)
	}
	s.DataDir = dd
	s.portFile = filepath.Join(dd, "control_port")
	_ = os.Remove(s.portFile) // чтобы не прочитать порт от прошлого запуска

	var b strings.Builder
	b.WriteString("# Файл создаётся tor-connect при каждом запуске из tecon.cfg. Не редактируйте его.\n")
	b.WriteString(cfg.TorText())
	b.WriteString("\n# --- добавлено tor-connect ---\n")
	if _, ok := cfg.Value("DataDirectory"); !ok {
		b.WriteString("DataDirectory " + q(dd) + "\n")
	}
	b.WriteString("Socks5Proxy " + s.ln.Addr().String() + "\n")
	b.WriteString("ControlPort auto\n")
	b.WriteString("ControlPortWriteToFile " + q(s.portFile) + "\n")
	b.WriteString("CookieAuthentication 1\n")
	b.WriteString("CookieAuthFile " + q(filepath.Join(dd, "control_auth_cookie")) + "\n")
	s.TorrcPath = filepath.Join(dd, "tor-connect.torrc")
	if err := os.WriteFile(s.TorrcPath, []byte(b.String()), 0o600); err != nil {
		s.Close()
		return nil, fmt.Errorf("не удалось записать %s: %w", s.TorrcPath, err)
	}
	s.TorArgs = append([]string{"-f", s.TorrcPath}, o.TorArgs...)
	return s, nil
}

func describe(specs []upstream.Spec) string {
	names := make([]string, len(specs))
	for i, sp := range specs {
		names[i] = sp.String()
	}
	return strings.Join(names, ", ")
}

func readConfig(p string) (string, fileStat, error) {
	st, err := os.Stat(p)
	if err != nil {
		return "", fileStat{}, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fileStat{}, err
	}
	return string(b), fileStat{st.ModTime(), st.Size()}, nil
}

// Close останавливает локальный маршрутизатор и управляющее соединение.
func (s *Session) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.ln != nil {
		s.ln.Close()
	}
	s.mu.Lock()
	if s.ctl != nil {
		s.ctl.Close()
		s.ctl = nil
	}
	s.mu.Unlock()
}

// StartControl ждёт, пока Tor запишет порт управления, и подключается к нему (до таймаута).
func (s *Session) StartControl(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	cookiePath := filepath.Join(s.DataDir, "control_auth_cookie")
	var lastErr error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		addr, err := tcontrol.ReadPortFile(s.portFile)
		if err == nil {
			var cookie []byte
			if cookie, err = os.ReadFile(cookiePath); err == nil {
				var c *tcontrol.Client
				if c, err = tcontrol.Dial(addr, 2*time.Second); err == nil {
					if err = c.AuthenticateCookie(cookie); err == nil {
						s.mu.Lock()
						s.ctl = c
						s.mu.Unlock()
						return nil
					}
					c.Close()
				}
			}
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	return fmt.Errorf("не удалось подключиться к управляющему порту Tor: %v", lastErr)
}

// Shutdown просит Tor завершиться. Возвращает false, если управляющего соединения нет.
func (s *Session) Shutdown() bool {
	s.mu.Lock()
	c := s.ctl
	s.mu.Unlock()
	if c == nil {
		return false
	}
	return c.Signal("SHUTDOWN") == nil
}

// Watch следит за файлом настроек и применяет изменения, пока не отменён ctx.
func (s *Session) Watch(ctx context.Context) {
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Poll()
		}
	}
}

// Poll проверяет файл настроек один раз и при изменении применяет его.
func (s *Session) Poll() {
	st, err := os.Stat(s.ConfigPath)
	if err != nil || (st.ModTime().Equal(s.lastStat.mod) && st.Size() == s.lastStat.size) {
		return
	}
	// редакторы пишут файл не мгновенно: ждём, пока он перестанет меняться
	time.Sleep(300 * time.Millisecond)
	text, st2, err := readConfig(s.ConfigPath)
	if err != nil {
		return
	}
	s.lastStat = st2
	if text == s.lastText {
		return
	}
	s.lastText = text
	s.reload(text)
}

func (s *Session) reload(text string) {
	cfg, err := tecon.Parse(text)
	if err != nil {
		s.logf("настройки не применены (ошибка в файле), действуют прежние: %v", err)
		return
	}
	for _, w := range cfg.Warnings {
		s.logf("предупреждение: %s", w)
	}
	s.logf("файл настроек изменён, применяю")

	if !s.cliUps && !sameList(cfg.Upstreams, s.Cfg.Upstreams) {
		specs, err := upstream.ParseSpecs(cfg.Upstreams)
		if err == nil {
			s.Dialer.SetSpecs(specs)
			if len(specs) == 0 {
				s.logf("вышестоящие прокси убраны: прямое подключение")
			} else {
				s.logf("вышестоящие прокси обновлены: %s", describe(specs))
			}
		}
	}

	changes := tecon.DiffTor(s.Cfg.Tor, cfg.Tor)
	s.mu.Lock()
	c := s.ctl
	s.mu.Unlock()
	applied := 0
	for _, ch := range changes {
		if c == nil {
			s.logf("%s: нет соединения с управляющим портом Tor, изменение применится после перезапуска", ch.Name)
			continue
		}
		if err := c.SetConf(ch.Name, ch.New...); err != nil {
			s.logf("%s: Tor не принял изменение (%v); возможно, для него нужен перезапуск программы", ch.Name, err)
			continue
		}
		applied++
		s.logf("%s: применено", ch.Name)
	}
	if len(changes) == 0 && sameList(cfg.Upstreams, s.Cfg.Upstreams) {
		s.logf("в настройках ничего не изменилось")
	}
	s.Cfg = cfg
}

func sameList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
