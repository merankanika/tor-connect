// Package app связывает части tor-connect: разбор аргументов, поиск и создание tecon.cfg,
// генерацию torrc для Tor, локальный маршрутизатор вышестоящих прокси, проброс портов, подключение к
// управляющему порту Tor и применение изменений конфигурации «на лету». Пакет не зависит от cgo.
package app

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/merankanika/tor-connect/internal/portmap"
	"github.com/merankanika/tor-connect/internal/socks5"
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

	Cfg    *tecon.Config
	Dialer *upstream.Dialer

	logf     func(format string, args ...any)
	cliUps   bool
	portFile string
	torSocks string // внутренний SocksPort Tor (для проброса портов через Tor)
	maps     *portmap.Manager

	ln     net.Listener
	cancel context.CancelFunc

	mu       sync.Mutex
	ctl      *tcontrol.Client
	ctx      context.Context
	lastStat fileStat
	lastText string
	effTor   []tecon.Directive // настройки Tor, фактически переданные Tor (без пропущенных занятых портов)
	pending  bool              // есть пропущенные порты: их стоит пробовать снова
	lastWarn string
}

type fileStat struct {
	mod  time.Time
	size int64
}

func q(p string) string { return tecon.QuotePath(p) }

// ---- проверка занятых портов ----

var tcpListenerOpts = map[string]bool{"socksport": true, "httptunnelport": true, "transport": true, "natdport": true}

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

// canBind проверяет, можно ли занять порт, указанный в директиве-слушателе Tor.
func canBind(key, value string) error {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return nil
	}
	tok := fields[0]
	if tok == "auto" || tok == "0" || strings.HasPrefix(tok, "unix:") {
		return nil
	}
	addr := tok
	if isDigits(tok) {
		addr = "127.0.0.1:" + tok
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil // формат необычный: пусть решает Tor
	}
	if key == "dnsport" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		return pc.Close()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// filterListeners убирает директивы-слушатели с занятыми портами, чтобы Tor не завершился с ошибкой.
// Значения, уже действующие у Tor (known), не проверяются: порт занят самим Tor.
func filterListeners(ds, known []tecon.Directive) (kept []tecon.Directive, warns []string) {
	have := map[string]bool{}
	for _, d := range known {
		have[strings.ToLower(d.Name)+"|"+d.Value] = true
	}
	for _, d := range ds {
		key := strings.ToLower(d.Name)
		if !tcpListenerOpts[key] && key != "dnsport" {
			kept = append(kept, d)
			continue
		}
		if key == "socksport" && strings.Fields(d.Value + " ")[0] == "0" {
			warns = append(warns, "SocksPort 0 игнорируется: у tor-connect всегда есть внутренний SocksPort")
			continue
		}
		if have[key+"|"+d.Value] {
			kept = append(kept, d)
			continue
		}
		if err := canBind(key, d.Value); err != nil {
			warns = append(warns, fmt.Sprintf("%s %s: порт занят или недоступен (%v); строка пропущена", d.Name, d.Value, err))
			continue
		}
		kept = append(kept, d)
	}
	return kept, warns
}

// ---- onion-службы ----

// Onion — служба Tor: каталог и виртуальные порты.
type Onion struct {
	Dir   string
	Ports []string
}

// OnionServices выделяет onion-службы из настроек Tor (HiddenServicePort относится к предыдущему HiddenServiceDir).
func OnionServices(ds []tecon.Directive) []Onion {
	var out []Onion
	for _, d := range ds {
		switch strings.ToLower(d.Name) {
		case "hiddenservicedir":
			out = append(out, Onion{Dir: tecon.UnquoteValue(d.Value)})
		case "hiddenserviceport":
			if len(out) > 0 {
				if f := strings.Fields(d.Value); len(f) > 0 {
					out[len(out)-1].Ports = append(out[len(out)-1].Ports, f[0])
				}
			}
		}
	}
	return out
}

func waitFile(ctx context.Context, path string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(300 * time.Millisecond):
		}
	}
	return ""
}

// AnnounceOnions сообщает адреса onion-служб, как только Tor их создаст.
func (s *Session) AnnounceOnions() {
	s.mu.Lock()
	ctx := s.ctx
	svcs := OnionServices(s.effTor)
	s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	for _, sv := range svcs {
		sv := sv
		go func() {
			host := waitFile(ctx, filepath.Join(sv.Dir, "hostname"), 120*time.Second)
			if host == "" {
				return
			}
			s.logf("onion-служба: %s (порты: %s)", host, strings.Join(sv.Ports, ", "))
		}()
	}
}

// ---- подготовка ----

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

// Prepare находит или создаёт файл настроек, разбирает его, запускает локальный маршрутизатор
// вышестоящих прокси и проброс портов и записывает torrc для Tor.
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
	cfg, err := tecon.ParseBase(text, filepath.Dir(s.ConfigPath))
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

	// 3. Каталог данных.
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

	// 4. Внутренний SocksPort Tor: нужен для проброса портов через Tor.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("не удалось выбрать внутренний порт Tor: %w", err)
	}
	s.torSocks = tmp.Addr().String()
	tmp.Close()

	// 5. Занятые порты пропускаем, а не падаем.
	eff, warns := filterListeners(cfg.Tor, nil)
	s.effTor = eff
	for _, w := range warns {
		s.Notes = append(s.Notes, "предупреждение: "+w)
	}
	s.lastWarn = strings.Join(warns, "\n")
	s.pending = len(warns) > 0

	var b strings.Builder
	b.WriteString("# Файл создаётся tor-connect при каждом запуске из tecon.cfg. Не редактируйте его.\n")
	b.WriteString(tecon.Text(eff))
	b.WriteString("\n# --- добавлено tor-connect ---\n")
	if _, ok := cfg.Value("DataDirectory"); !ok {
		b.WriteString("DataDirectory " + q(dd) + "\n")
	}
	b.WriteString("SocksPort " + s.torSocks + "\n")
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

	// 6. Проброс портов.
	s.maps = portmap.NewManager(portmap.Dialers{
		Tor:      s.dialTor,
		Direct:   (&net.Dialer{}).DialContext,
		Upstream: s.Dialer.DialContext,
	}, logf)
	if len(cfg.Maps) > 0 {
		run, skipped := s.maps.Apply(cfg.Maps)
		s.Notes = append(s.Notes, fmt.Sprintf("проброс портов: работает %d, пропущено %d", run, skipped))
		if skipped > 0 {
			s.pending = true
		}
	}
	return s, nil
}

// dialTor подключается к назначению через внутренний SocksPort Tor (для проброса портов).
func (s *Session) dialTor(ctx context.Context, host string, port int, isolation string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", s.torSocks)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	user := fmt.Sprintf("pm-%x", sha1.Sum([]byte(isolation)))[:19]
	if err := socks5.ClientHandshake(c, host, port, user, "x"); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// Close останавливает локальный маршрутизатор, проброс портов и управляющее соединение.
func (s *Session) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.ln != nil {
		s.ln.Close()
	}
	if s.maps != nil {
		s.maps.Close()
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
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()
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
// Раз в 30 секунд заново пробует пропущенные (занятые) порты.
func (s *Session) Watch(ctx context.Context) {
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	retry := time.NewTicker(30 * time.Second)
	defer retry.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Poll()
		case <-retry.C:
			s.Refresh()
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
	cfg, err := tecon.ParseBase(text, filepath.Dir(s.ConfigPath))
	if err != nil {
		s.logf("настройки не применены (ошибка в файле), действуют прежние: %v", err)
		return
	}
	for _, w := range cfg.Warnings {
		s.logf("предупреждение: %s", w)
	}
	s.logf("файл настроек изменён, применяю")
	s.applyConfig(cfg, false)
}

// Refresh заново пробует пропущенные порты, если такие есть.
func (s *Session) Refresh() {
	if s.pending {
		s.applyConfig(s.Cfg, true)
	}
}

func (s *Session) warnOnce(warns []string) {
	joined := strings.Join(warns, "\n")
	if joined == s.lastWarn {
		return
	}
	s.lastWarn = joined
	for _, w := range warns {
		s.logf("предупреждение: %s", w)
	}
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

func values(vs []string) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = tecon.UnquoteValue(v)
	}
	return out
}

func (s *Session) applyConfig(cfg *tecon.Config, quiet bool) {
	changedAny := false

	if !s.cliUps && !sameList(cfg.Upstreams, s.Cfg.Upstreams) {
		if specs, err := upstream.ParseSpecs(cfg.Upstreams); err == nil {
			s.Dialer.SetSpecs(specs)
			changedAny = true
			if len(specs) == 0 {
				s.logf("вышестоящие прокси убраны: прямое подключение")
			} else {
				s.logf("вышестоящие прокси обновлены: %s", describe(specs))
			}
		}
	}

	eff, warns := filterListeners(cfg.Tor, s.effTor)
	s.warnOnce(warns)
	changes := tecon.DiffTor(s.effTor, eff)
	s.mu.Lock()
	c := s.ctl
	s.mu.Unlock()
	onionChanged := false
	for _, ch := range changes {
		changedAny = true
		if c == nil {
			s.logf("%s: нет соединения с управляющим портом Tor, изменение применится после перезапуска", ch.Name)
			continue
		}
		var err error
		switch {
		case ch.Group && len(ch.Pairs) > 0:
			pairs := make([]tcontrol.Pair, len(ch.Pairs))
			for i, p := range ch.Pairs {
				pairs[i] = tcontrol.Pair{Name: p.Name, Value: tecon.UnquoteValue(p.Value)}
			}
			err = c.SetConfPairs(pairs)
			onionChanged = err == nil
		case ch.Group:
			err = c.ResetConf(ch.ResetNames...)
		default:
			err = c.SetConf(ch.Name, values(ch.New)...)
		}
		if err != nil {
			s.logf("%s: Tor не принял изменение (%v); возможно, для него нужен перезапуск программы", ch.Name, err)
			continue
		}
		s.logf("%s: применено", ch.Name)
	}
	s.effTor = eff

	skippedMaps := 0
	if s.maps != nil {
		run, skipped := s.maps.Apply(cfg.Maps)
		skippedMaps = skipped
		if !sameMaps(cfg.Maps, s.Cfg.Maps) {
			changedAny = true
			s.logf("проброс портов: работает %d, пропущено %d", run, skipped)
		}
	}
	s.pending = len(warns) > 0 || skippedMaps > 0
	s.Cfg = cfg
	if onionChanged {
		s.AnnounceOnions()
	}
	if !changedAny && !quiet {
		s.logf("в настройках ничего не изменилось")
	}
}

func sameMaps(a, b []portmap.Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Key() != b[i].Key() {
			return false
		}
	}
	return true
}
