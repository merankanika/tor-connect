package app

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	o, err := ParseArgs([]string{"--version"})
	if err != nil || !o.Passthrough || len(o.TorArgs) != 1 {
		t.Fatalf("%+v %v", o, err)
	}
	o, err = ParseArgs([]string{"my.cfg", "-upstream", "direct", "--upstream", "socks5://h:1", "--Log", "notice stdout"})
	if err != nil {
		t.Fatal(err)
	}
	if o.ConfigPath != "my.cfg" || len(o.Upstreams) != 2 || len(o.TorArgs) != 2 || o.TorArgs[0] != "--Log" {
		t.Fatalf("%+v", o)
	}
	o, _ = ParseArgs([]string{"-f", "a.cfg"})
	if o.ConfigPath != "a.cfg" {
		t.Fatalf("%+v", o)
	}
	o, _ = ParseArgs([]string{"-c", "b.cfg"})
	if o.ConfigPath != "b.cfg" {
		t.Fatalf("%+v", o)
	}
	for _, bad := range [][]string{{"-f"}, {"-upstream"}} {
		if _, err := ParseArgs(bad); err == nil {
			t.Fatalf("ожидалась ошибка для %v", bad)
		}
	}
	if o, _ := ParseArgs(nil); o.ConfigPath != "" || o.Passthrough {
		t.Fatalf("пустые аргументы: %+v", o)
	}
}

func prepare(t *testing.T, o Options, exe, cwd string) *Session {
	t.Helper()
	s, err := Prepare(o, exe, cwd, func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestPrepareCreatesDefaults(t *testing.T) {
	exe, cwd := t.TempDir(), t.TempDir()
	s := prepare(t, Options{}, exe, cwd)
	if s.ConfigPath != filepath.Join(exe, "tecon.cfg") {
		t.Fatalf("путь конфига: %s", s.ConfigPath)
	}
	if s.DataDir != filepath.Join(exe, "data") {
		t.Fatalf("каталог данных: %s", s.DataDir)
	}
	b, err := os.ReadFile(s.TorrcPath)
	if err != nil {
		t.Fatal(err)
	}
	txt := string(b)
	for _, want := range []string{"SocksPort 127.0.0.1:9050", "Socks5Proxy 127.0.0.1:", "ControlPort auto", "ControlPortWriteToFile", "CookieAuthentication 1", "DataDirectory \""} {
		if !strings.Contains(txt, want) {
			t.Fatalf("в torrc нет %q:\n%s", want, txt)
		}
	}
	if len(s.TorArgs) < 2 || s.TorArgs[0] != "-f" || s.TorArgs[1] != s.TorrcPath {
		t.Fatalf("аргументы Tor: %v", s.TorArgs)
	}
}

func TestPrepareUsesExistingAndDataDirectory(t *testing.T) {
	exe, cwd := t.TempDir(), t.TempDir()
	dd := filepath.Join(t.TempDir(), "my data")
	cfg := "SocksPort 1234\nDataDirectory \"" + filepath.ToSlash(dd) + "\"\nUpstream direct\n"
	os.WriteFile(filepath.Join(cwd, "tecon"), []byte(cfg), 0o644)
	s := prepare(t, Options{}, exe, cwd)
	if s.ConfigPath != filepath.Join(cwd, "tecon") {
		t.Fatalf("должен использоваться файл из рабочей папки: %s", s.ConfigPath)
	}
	if s.DataDir != dd {
		t.Fatalf("DataDirectory из конфига: %s", s.DataDir)
	}
	b, _ := os.ReadFile(s.TorrcPath)
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "DataDirectory ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("DataDirectory не должен дублироваться:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(exe, "tecon.cfg")); !os.IsNotExist(err) {
		t.Fatal("новый файл создаваться не должен")
	}
	if got := s.Dialer.Specs(); len(got) != 1 || got[0].Kind != "direct" {
		t.Fatalf("upstream из файла: %+v", got)
	}
}

func TestPrepareExplicitConfigAndCLIUpstream(t *testing.T) {
	exe, cwd := t.TempDir(), t.TempDir()
	p := filepath.Join(t.TempDir(), "x.cfg")
	os.WriteFile(p, []byte("Upstream socks5://file:1080\n"), 0o644)
	s := prepare(t, Options{ConfigPath: p, Upstreams: []string{"http://cli:8080"}}, exe, cwd)
	got := s.Dialer.Specs()
	if len(got) != 1 || got[0].Kind != "http" || got[0].Addr != "cli:8080" {
		t.Fatalf("-upstream должен заменять строки из файла: %+v", got)
	}
	// несуществующий явный путь создаётся
	p2 := filepath.Join(t.TempDir(), "new.cfg")
	prepare(t, Options{ConfigPath: p2}, exe, cwd)
	if _, err := os.Stat(p2); err != nil {
		t.Fatal("явно указанный файл должен создаваться")
	}
}

func TestPrepareBadConfig(t *testing.T) {
	exe := t.TempDir()
	os.WriteFile(filepath.Join(exe, "tecon.cfg"), []byte("Upstream ftp://x\n"), 0o644)
	if _, err := Prepare(Options{}, exe, exe, nil); err == nil {
		t.Fatal("ожидалась ошибка разбора")
	}
}

// fakeTor — управляющий порт, принимающий cookie и записывающий команды.
type fakeTor struct {
	mu   sync.Mutex
	cmds []string
	addr string
}

func startFakeTor(t *testing.T, cookie []byte, reject string) *fakeTor {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeTor{addr: ln.Addr().String()}
	want := "AUTHENTICATE " + hex.EncodeToString(cookie)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					l = strings.TrimRight(l, "\r\n")
					f.mu.Lock()
					f.cmds = append(f.cmds, l)
					f.mu.Unlock()
					switch {
					case strings.HasPrefix(l, "AUTHENTICATE") && l != want:
						c.Write([]byte("515 Authentication failed\r\n"))
					case reject != "" && strings.HasPrefix(l, "SETCONF "+reject):
						c.Write([]byte("513 Unable to change option\r\n"))
					default:
						c.Write([]byte("250 OK\r\n"))
					}
				}
			}()
		}
	}()
	return f
}

func (f *fakeTor) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds...)
}

func connect(t *testing.T, s *Session, f *fakeTor, cookie []byte) {
	t.Helper()
	os.WriteFile(filepath.Join(s.DataDir, "control_auth_cookie"), cookie, 0o600)
	os.WriteFile(s.portFile, []byte("PORT="+f.addr+"\n"), 0o644)
	if err := s.StartControl(context.Background(), 3*time.Second); err != nil {
		t.Fatal(err)
	}
}

func rewrite(t *testing.T, s *Session, text string) {
	t.Helper()
	if err := os.WriteFile(s.ConfigPath, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Duration(len(text)+1) * time.Second)
	os.Chtimes(s.ConfigPath, future, future)
	s.Poll()
}

func TestLiveReload(t *testing.T) {
	exe := t.TempDir()
	os.WriteFile(filepath.Join(exe, "tecon.cfg"), []byte("SocksPort 9050\nLog notice stdout\nBridge a\n"), 0o644)
	s := prepare(t, Options{}, exe, exe)
	cookie := []byte{1, 2, 3, 4}
	f := startFakeTor(t, cookie, "DataDirectory")
	connect(t, s, f, cookie)

	// изменение настроек Tor + вышестоящий прокси
	rewrite(t, s, "SocksPort 9050\nBridge a\nBridge b\nExitNodes {de}\nUpstream socks5://u:p@10.0.0.1:1080\n")
	cmds := strings.Join(f.commands(), "\n")
	for _, want := range []string{`SETCONF Bridge="a" Bridge="b"`, `SETCONF ExitNodes="{de}"`, "SETCONF Log"} {
		if !strings.Contains(cmds, want) {
			t.Fatalf("нет команды %q среди:\n%s", want, cmds)
		}
	}
	if strings.Contains(cmds, "SETCONF SocksPort") {
		t.Fatal("неизменённая настройка не должна отправляться")
	}
	sp := s.Dialer.Specs()
	if len(sp) != 1 || sp[0].Kind != "socks5" || sp[0].User != "u" {
		t.Fatalf("upstream после перезагрузки: %+v", sp)
	}

	// ошибка в файле: прежние настройки остаются
	before := len(f.commands())
	rewrite(t, s, "SocksPort 1\nUpstream ftp://bad\n")
	if len(f.commands()) != before || len(s.Dialer.Specs()) != 1 || s.Dialer.Specs()[0].Kind != "socks5" {
		t.Fatal("при ошибке в файле ничего применяться не должно")
	}

	// настройка, которую Tor не принимает на лету: остальные всё равно применяются
	rewrite(t, s, "SocksPort 9050\nBridge a\nBridge b\nExitNodes {nl}\nDataDirectory D:/other\nUpstream direct\n")
	cmds = strings.Join(f.commands(), "\n")
	if !strings.Contains(cmds, `SETCONF ExitNodes="{nl}"`) || !strings.Contains(cmds, "SETCONF DataDirectory") {
		t.Fatalf("ожидались ExitNodes и попытка DataDirectory:\n%s", cmds)
	}
	if sp := s.Dialer.Specs(); len(sp) != 1 || sp[0].Kind != "direct" {
		t.Fatalf("upstream: %+v", sp)
	}
}

func TestReloadKeepsCLIUpstream(t *testing.T) {
	exe := t.TempDir()
	s := prepare(t, Options{Upstreams: []string{"socks5://cli:1"}}, exe, exe)
	cookie := []byte{9}
	f := startFakeTor(t, cookie, "")
	connect(t, s, f, cookie)
	rewrite(t, s, "SocksPort 9050\nUpstream direct\n")
	if sp := s.Dialer.Specs(); len(sp) != 1 || sp[0].Addr != "cli:1" {
		t.Fatalf("-upstream из командной строки не должен меняться при перезагрузке: %+v", sp)
	}
}

func TestShutdownWithoutControl(t *testing.T) {
	exe := t.TempDir()
	s := prepare(t, Options{}, exe, exe)
	if s.Shutdown() {
		t.Fatal("без управляющего соединения Shutdown должен вернуть false")
	}
}

func TestStartControlTimeout(t *testing.T) {
	exe := t.TempDir()
	s := prepare(t, Options{}, exe, exe)
	if err := s.StartControl(context.Background(), 600*time.Millisecond); err == nil {
		t.Fatal("ожидалась ошибка таймаута")
	}
}

// ---- занятые порты, onion-службы, проброс портов ----

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func prepareLog(t *testing.T, cfg string) (*Session, func() []string, string) {
	t.Helper()
	exe := t.TempDir()
	if err := os.WriteFile(filepath.Join(exe, "tecon.cfg"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var logs []string
	s, err := Prepare(Options{}, exe, exe, func(f string, a ...any) {
		mu.Lock()
		logs = append(logs, fmtSprintf(f, a...))
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), logs...)
	}, exe
}

func TestBusyListenerPortsAreSkipped(t *testing.T) {
	busyTCP, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busyTCP.Close()
	busyUDP, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer busyUDP.Close()
	good := freeAddr(t)
	cfg := "SocksPort " + busyTCP.Addr().String() + "\nSocksPort " + good + " IsolateClientAddr\nDNSPort " + busyUDP.LocalAddr().String() + "\nHTTPTunnelPort auto\nSocksPort auto\n"
	s, _, _ := prepareLog(t, cfg)
	b, _ := os.ReadFile(s.TorrcPath)
	txt := string(b)
	if strings.Contains(txt, busyTCP.Addr().String()) || strings.Contains(txt, busyUDP.LocalAddr().String()) {
		t.Fatalf("занятые порты не должны попадать в torrc:\n%s", txt)
	}
	for _, want := range []string{"SocksPort " + good, "HTTPTunnelPort auto", "SocksPort auto", "SocksPort " + s.torSocks} {
		if !strings.Contains(txt, want) {
			t.Fatalf("в torrc нет %q:\n%s", want, txt)
		}
	}
	warns := 0
	for _, n := range s.Notes {
		if strings.Contains(n, "порт занят") {
			warns++
		}
	}
	if warns != 2 {
		t.Fatalf("ожидалось 2 предупреждения о занятых портах: %v", s.Notes)
	}
}

func TestRetryPortWhenItBecomesFree(t *testing.T) {
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := busy.Addr().String()
	s, _, _ := prepareLog(t, "SocksPort "+addr+"\n")
	cookie := []byte{7}
	f := startFakeTor(t, cookie, "")
	connect(t, s, f, cookie)
	if !s.pending {
		t.Fatal("пропущенный порт должен помечать сеанс как ожидающий")
	}
	s.Refresh()
	if strings.Contains(strings.Join(f.commands(), "\n"), "SETCONF SocksPort") {
		t.Fatal("порт ещё занят, команды быть не должно")
	}
	busy.Close()
	s.Refresh()
	if !strings.Contains(strings.Join(f.commands(), "\n"), `SETCONF SocksPort="`+addr+`"`) {
		t.Fatalf("после освобождения порт должен быть передан Tor: %v", f.commands())
	}
	if s.pending {
		t.Fatal("после успешного применения ожидающих портов не остаётся")
	}
}

func TestHiddenServicesGroupedReload(t *testing.T) {
	s, _, exe := prepareLog(t, "Log notice stdout\n")
	cookie := []byte{5}
	f := startFakeTor(t, cookie, "")
	connect(t, s, f, cookie)

	spaced := filepath.ToSlash(filepath.Join(t.TempDir(), "my dir", "hs"))
	rewrite(t, s, "Log notice stdout\nHiddenServiceDir hs/main\nHiddenServiceVersion 3\nHiddenServicePort 21\nHiddenServicePort 22 127.0.0.1:22\nHiddenServicePort 80 127.0.0.1:8080\nHiddenServiceDir \""+spaced+"\"\nHiddenServicePort 3389 127.0.0.1:1805\n")
	want := `SETCONF HiddenServiceDir="` + filepath.ToSlash(filepath.Join(exe, "hs", "main")) + `" HiddenServiceVersion="3" HiddenServicePort="21" HiddenServicePort="22 127.0.0.1:22" HiddenServicePort="80 127.0.0.1:8080" HiddenServiceDir="` + spaced + `" HiddenServicePort="3389 127.0.0.1:1805"`
	cmds := f.commands()
	if got := cmds[len(cmds)-1]; got != want {
		t.Fatalf("семья HiddenService* должна уходить одной командой в порядке файла:\n%s\n%s", got, want)
	}
	n := 0
	for _, c := range cmds {
		if strings.HasPrefix(c, "SETCONF HiddenService") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("ожидалась одна команда, а не %d", n)
	}
	rewrite(t, s, "Log notice stdout\n")
	cmds = f.commands()
	if got := cmds[len(cmds)-1]; got != "SETCONF HiddenServiceDir HiddenServiceVersion HiddenServicePort" {
		t.Fatalf("сброс служб: %q", got)
	}
}

func TestOnionServicesAndAnnounce(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir())
	s, getLogs, _ := prepareLog(t, "HiddenServiceDir \""+dir+"\"\nHiddenServicePort 22 127.0.0.1:22\nHiddenServicePort 80\n")
	svcs := OnionServices(s.effTor)
	if len(svcs) != 1 || svcs[0].Dir != dir || strings.Join(svcs[0].Ports, ",") != "22,80" {
		t.Fatalf("%+v", svcs)
	}
	os.WriteFile(filepath.Join(dir, "hostname"), []byte("abcdefghijklmnop.onion\n"), 0o600)
	s.AnnounceOnions()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, l := range getLogs() {
			if strings.Contains(l, "abcdefghijklmnop.onion") && strings.Contains(l, "22, 80") {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("адрес onion-службы не объявлен: %v", getLogs())
}

func echoServer(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				io.WriteString(c, "echo:"+line)
			}()
		}
	}()
	return ln.Addr().String()
}

func askTCP(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "ошибка: " + err.Error()
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "hi\n")
	l, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(l)
}

func TestMapPortLifecycle(t *testing.T) {
	echo := echoServer(t)
	listen := freeAddr(t)
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	cfg := "MapPort " + listen + " to " + echo + "\nMapPort " + busy.Addr().String() + " to " + echo + "\n"
	s, _, _ := prepareLog(t, cfg)
	if got := askTCP(t, listen); got != "echo:hi" {
		t.Fatalf("проброс не работает: %q", got)
	}
	found := false
	for _, n := range s.Notes {
		if strings.Contains(n, "работает 1, пропущено 1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("итог проброса в сообщениях запуска: %v", s.Notes)
	}
	cookie := []byte{3}
	f := startFakeTor(t, cookie, "")
	connect(t, s, f, cookie)
	rewrite(t, s, "Log notice stdout\n") // правила убраны
	time.Sleep(150 * time.Millisecond)
	if got := askTCP(t, listen); !strings.HasPrefix(got, "ошибка") {
		t.Fatalf("после удаления правила порт должен закрыться: %q", got)
	}
	if strings.Contains(strings.Join(f.commands(), "\n"), "MapPort") {
		t.Fatal("MapPort — директива tor-connect, Tor её получать не должен")
	}
}

func fmtSprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }
