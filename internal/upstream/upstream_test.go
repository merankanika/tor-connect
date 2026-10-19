package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/merankanika/tor-connect/internal/socks5"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// echoServer отвечает «echo:» + принятая строка.
func echoServer(t *testing.T) string {
	ln := listen(t)
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

// socksProxy — тестовый SOCKS5-прокси; если wantUser не пуст, требует авторизацию.
func socksProxy(t *testing.T, wantUser, wantPass string, hits *int32) string {
	ln := listen(t)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				atomic.AddInt32(hits, 1)
				req, err := socks5.ReadRequest(c, wantUser != "")
				if err != nil {
					return
				}
				if wantUser != "" && (req.User != wantUser || req.Pass != wantPass) {
					return
				}
				up, err := net.Dial("tcp", req.Addr())
				if err != nil {
					socks5.Reply(c, socks5.ReplyHostUnreachable)
					return
				}
				defer up.Close()
				socks5.Reply(c, socks5.ReplyOK)
				Pipe(c, up)
			}()
		}
	}()
	return ln.Addr().String()
}

// httpProxy — тестовый HTTP CONNECT-прокси с Basic-авторизацией.
func httpProxy(t *testing.T, user, pass string) string {
	ln := listen(t)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != "CONNECT" {
					return
				}
				if req.Header.Get("Proxy-Authorization") != want {
					io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				Pipe(&bufConn{Conn: c, r: br}, up)
			}()
		}
	}()
	return ln.Addr().String()
}

func deadAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().String()
	ln.Close()
	return a
}

func roundtrip(t *testing.T, c net.Conn) string {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "hi\n")
	s, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(s)
}

func TestParseSpec(t *testing.T) {
	s, err := ParseSpec("socks5://bob:p%40ss@10.0.0.1:9050")
	if err != nil || s.Kind != "socks5" || s.Addr != "10.0.0.1:9050" || s.User != "bob" || s.Pass != "p@ss" {
		t.Fatalf("%+v %v", s, err)
	}
	if s, _ := ParseSpec("http://proxy.local"); s.Addr != "proxy.local:8080" {
		t.Fatalf("порт по умолчанию: %+v", s)
	}
	if s, _ := ParseSpec("DIRECT"); s.Kind != "direct" {
		t.Fatal("direct")
	}
	if _, err := ParseSpec("ftp://x:1"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if got := (Spec{Kind: "http", Addr: "a:1", User: "u", Pass: "secret"}).String(); strings.Contains(got, "secret") {
		t.Fatal("пароль не должен попадать в журнал")
	}
}

func TestFailoverToDirect(t *testing.T) {
	echo := echoServer(t)
	d := New([]Spec{
		{Kind: "socks5", Addr: deadAddr(t)},
		{Kind: "direct"},
	}, Options{AttemptTimeout: time.Second})
	c, err := d.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundtrip(t, c); got != "echo:hi" {
		t.Fatal(got)
	}
}

func TestSocks5WithAuth(t *testing.T) {
	echo := echoServer(t)
	var hits int32
	px := socksProxy(t, "bob", "pw", &hits)
	d := New([]Spec{{Kind: "socks5", Addr: px, User: "bob", Pass: "pw"}}, Options{})
	c, err := d.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundtrip(t, c); got != "echo:hi" {
		t.Fatal(got)
	}
	bad := New([]Spec{{Kind: "socks5", Addr: px, User: "bob", Pass: "WRONG"}}, Options{AttemptTimeout: time.Second})
	if _, err := bad.DialContext(context.Background(), "tcp", echo); err == nil {
		t.Fatal("с неверным паролем подключение не должно проходить")
	}
}

func TestHTTPConnectWithAuth(t *testing.T) {
	echo := echoServer(t)
	px := httpProxy(t, "u", "p")
	d := New([]Spec{{Kind: "http", Addr: px, User: "u", Pass: "p"}}, Options{})
	c, err := d.DialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatal(err)
	}
	if got := roundtrip(t, c); got != "echo:hi" {
		t.Fatal(got)
	}
	bad := New([]Spec{{Kind: "http", Addr: px, User: "u", Pass: "x"}}, Options{AttemptTimeout: time.Second})
	if _, err := bad.DialContext(context.Background(), "tcp", echo); err == nil {
		t.Fatal("ожидалась ошибка 407")
	}
}

func TestStickyAndCooldown(t *testing.T) {
	echo := echoServer(t)
	var deadHits int32
	// первый прокси отвергает всё (авторизация не совпадает), второй — прямое подключение
	first := socksProxy(t, "x", "y", &deadHits)
	d := New([]Spec{
		{Kind: "socks5", Addr: first, User: "bad", Pass: "bad"},
		{Kind: "direct"},
	}, Options{AttemptTimeout: time.Second, Cooldown: time.Minute})
	for i := 0; i < 5; i++ {
		c, err := d.DialContext(context.Background(), "tcp", echo)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if n := atomic.LoadInt32(&deadHits); n != 1 {
		t.Fatalf("сбойный прокси должен пробоваться один раз за период охлаждения, а не %d", n)
	}
}

func TestAllFail(t *testing.T) {
	d := New([]Spec{{Kind: "socks5", Addr: deadAddr(t)}, {Kind: "http", Addr: deadAddr(t)}}, Options{AttemptTimeout: time.Second})
	if _, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestRouterEndToEnd(t *testing.T) {
	echo := echoServer(t)
	d := New([]Spec{{Kind: "socks5", Addr: deadAddr(t)}, {Kind: "direct"}}, Options{AttemptTimeout: time.Second})
	ln := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, ln, d)

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	host, portStr, _ := net.SplitHostPort(echo)
	var port int
	for _, ch := range portStr {
		port = port*10 + int(ch-'0')
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5.ClientHandshake(c, host, port, "", ""); err != nil {
		t.Fatal(err)
	}
	if got := roundtrip(t, c); got != "echo:hi" {
		t.Fatal(got)
	}
}
