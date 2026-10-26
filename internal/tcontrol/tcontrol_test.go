package tcontrol

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTor — упрощённый управляющий порт: принимает cookie, записывает команды.
type fakeTor struct {
	mu   sync.Mutex
	cmds []string
	ln   net.Listener
}

func newFakeTor(t *testing.T, cookieHex string) *fakeTor {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTor{ln: ln}
	t.Cleanup(func() { ln.Close() })
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
					case strings.HasPrefix(l, "AUTHENTICATE "):
						if strings.TrimPrefix(l, "AUTHENTICATE ") == cookieHex {
							c.Write([]byte("250 OK\r\n"))
						} else {
							c.Write([]byte("515 Authentication failed\r\n"))
						}
					case strings.HasPrefix(l, "SETCONF Bad"):
						c.Write([]byte("513 Unacceptable option value\r\n"))
					case strings.HasPrefix(l, "GETINFO multi"):
						c.Write([]byte("250+multi=\r\nline1\r\n..dot\r\n.\r\n250 OK\r\n"))
					case strings.HasPrefix(l, "GETINFO version"):
						c.Write([]byte("250-version=0.4.9.11\r\n250 OK\r\n"))
					default:
						c.Write([]byte("250 OK\r\n"))
					}
				}
			}()
		}
	}()
	return f
}

func (f *fakeTor) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cmds) == 0 {
		return ""
	}
	return f.cmds[len(f.cmds)-1]
}

func TestAuthAndCommands(t *testing.T) {
	f := newFakeTor(t, "0102ff")
	c, err := Dial(f.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.AuthenticateCookie([]byte{0x01, 0x02, 0xff}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetConf("ExitNodes", "{de}", "{nl}"); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got != `SETCONF ExitNodes="{de}" ExitNodes="{nl}"` {
		t.Fatalf("SETCONF: %q", got)
	}
	if err := c.SetConf("Bridge"); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got != "SETCONF Bridge" {
		t.Fatalf("сброс: %q", got)
	}
	if err := c.SetConf("Log", `notice file C:\tor "x".log`); err != nil {
		t.Fatal(err)
	}
	if got := f.last(); got != `SETCONF Log="notice file C:\\tor \"x\".log"` {
		t.Fatalf("экранирование: %q", got)
	}
	if v, err := c.GetInfo("version"); err != nil || v != "0.4.9.11" {
		t.Fatalf("GETINFO: %q %v", v, err)
	}
	if v, err := c.GetInfo("multi"); err != nil || v != "\nline1\n.dot" {
		t.Fatalf("многострочный ответ: %q %v", v, err)
	}
	if err := c.SetConf("BadOption", "1"); err == nil || !strings.Contains(err.Error(), "513") {
		t.Fatalf("ожидалась ошибка 513: %v", err)
	}
	if err := c.Signal("SHUTDOWN"); err != nil || f.last() != "SIGNAL SHUTDOWN" {
		t.Fatalf("SIGNAL: %v %q", err, f.last())
	}
}

func TestAuthFailure(t *testing.T) {
	f := newFakeTor(t, "aa")
	c, err := Dial(f.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.AuthenticateCookie([]byte{0xbb}); err == nil {
		t.Fatal("ожидалась ошибка аутентификации")
	}
}

func TestNoNewlineInjection(t *testing.T) {
	f := newFakeTor(t, "aa")
	c, _ := Dial(f.ln.Addr().String(), time.Second)
	defer c.Close()
	if _, err := c.Cmd("GETINFO version\r\nSIGNAL HALT"); err == nil {
		t.Fatal("перевод строки в команде должен отклоняться")
	}
}

func TestReadPortFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "control_port")
	os.WriteFile(p, []byte("PORT=127.0.0.1:49152\n"), 0o644)
	if a, err := ReadPortFile(p); err != nil || a != "127.0.0.1:49152" {
		t.Fatalf("%q %v", a, err)
	}
	os.WriteFile(p, []byte("мусор\n"), 0o644)
	if _, err := ReadPortFile(p); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestSetConfPairsAndReset(t *testing.T) {
	f := newFakeTor(t, "aa")
	c, _ := Dial(f.ln.Addr().String(), time.Second)
	defer c.Close()
	if err := c.AuthenticateCookie([]byte{0xaa}); err != nil {
		t.Fatal(err)
	}
	err := c.SetConfPairs([]Pair{{"HiddenServiceDir", "D:/hs/a"}, {"HiddenServicePort", "22 127.0.0.1:22"}, {"HiddenServiceDir", "D:/hs/b"}, {"HiddenServicePort", "80 127.0.0.1:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `SETCONF HiddenServiceDir="D:/hs/a" HiddenServicePort="22 127.0.0.1:22" HiddenServiceDir="D:/hs/b" HiddenServicePort="80 127.0.0.1:8080"`
	if got := f.last(); got != want {
		t.Fatalf("порядок пар должен сохраняться:\n%q\n%q", got, want)
	}
	if err := c.ResetConf("HiddenServiceDir", "HiddenServicePort"); err != nil || f.last() != "SETCONF HiddenServiceDir HiddenServicePort" {
		t.Fatalf("%v %q", err, f.last())
	}
	if c.SetConfPairs(nil) == nil || c.ResetConf() == nil {
		t.Fatal("пустые списки должны давать ошибку")
	}
}
