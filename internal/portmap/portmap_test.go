package portmap

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseRule(t *testing.T) {
	cases := []struct {
		proto, in           string
		listen, target, via string
		wantErr             bool
	}{
		{"tcp", "127.0.0.1:122 to 155.33.11.22:22", "127.0.0.1:122", "155.33.11.22:22", "tor", false},
		{"tcp", "127.0.0.1:555 to 125", "127.0.0.1:555", "127.0.0.1:125", "direct", false},
		{"tcp", "143 to 144.33.44.17:1146", "0.0.0.0:143", "144.33.44.17:1146", "tor", false},
		{"tcp", "8080 TO abcdefghijklmnop.onion:80", "0.0.0.0:8080", "abcdefghijklmnop.onion:80", "tor", false},
		{"tcp", "8080 to 10.0.0.5:80", "0.0.0.0:8080", "10.0.0.5:80", "direct", false},
		{"tcp", "8080 to 10.0.0.5:80 via TOR", "0.0.0.0:8080", "10.0.0.5:80", "tor", false},
		{"tcp", "8080 to example.com:443 via upstream", "0.0.0.0:8080", "example.com:443", "upstream", false},
		{"tcp", "[::1]:99 to 98", "[::1]:99", "127.0.0.1:98", "direct", false},
		{"udp", "127.0.0.1:122 to 155.33.11.22:22", "127.0.0.1:122", "155.33.11.22:22", "direct", false},
		{"udp", "143 to 1146", "0.0.0.0:143", "127.0.0.1:1146", "direct", false},
		{"udp", "143 to 1.2.3.4:5 via tor", "", "", "", true},
		{"udp", "143 to abc.onion:5", "", "", "", true},
		{"tcp", "8080 to abc.onion:80 via direct", "", "", "", true},
		{"tcp", "8080 1.2.3.4:5", "", "", "", true},
		{"tcp", "0 to 5", "", "", "", true},
		{"tcp", "70000 to 5", "", "", "", true},
		{"tcp", "8080 to 5 via", "", "", "", true},
		{"tcp", "8080 to 5 via magic", "", "", "", true},
		{"tcp", "8080 to 5 extra words here", "", "", "", true},
		{"icmp", "8080 to 5", "", "", "", true},
	}
	for _, c := range cases {
		r, err := ParseRule(c.proto, c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s %q: ожидалась ошибка, получено %+v", c.proto, c.in, r)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s %q: %v", c.proto, c.in, err)
			continue
		}
		if r.Listen != c.listen || r.Target != c.target || r.Via != c.via || r.Proto != c.proto {
			t.Errorf("%s %q: получено %+v, ожидалось %s → %s (%s)", c.proto, c.in, r, c.listen, c.target, c.via)
		}
	}
}

func freeTCP(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func echoTCP(t *testing.T) string {
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

func ask(t *testing.T, addr string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "hi\n")
	s, _ := bufio.NewReader(c).ReadString('\n')
	return strings.TrimSpace(s)
}

func TestTCPDirect(t *testing.T) {
	echo := echoTCP(t)
	listen := freeTCP(t)
	m := NewManager(Dialers{}, nil)
	defer m.Close()
	run, skip := m.Apply([]Rule{{Proto: "tcp", Listen: listen, Target: echo, Via: "direct"}})
	if run != 1 || skip != 0 {
		t.Fatalf("run=%d skip=%d", run, skip)
	}
	if got := ask(t, listen); got != "echo:hi" {
		t.Fatal(got)
	}
}

func TestTCPViaTorUsesSocksDialer(t *testing.T) {
	echo := echoTCP(t)
	listen := freeTCP(t)
	var mu sync.Mutex
	var gotHost string
	var gotPort int
	var gotIso string
	d := Dialers{Tor: func(ctx context.Context, host string, port int, iso string) (net.Conn, error) {
		mu.Lock()
		gotHost, gotPort, gotIso = host, port, iso
		mu.Unlock()
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", echo) // «Tor» ведёт к тестовому эхо-серверу
	}}
	m := NewManager(d, nil)
	defer m.Close()
	m.Apply([]Rule{{Proto: "tcp", Listen: listen, Target: "example.onion:22", Via: "tor"}})
	if got := ask(t, listen); got != "echo:hi" {
		t.Fatal(got)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotHost != "example.onion" || gotPort != 22 || !strings.HasPrefix(gotIso, "portmap:") {
		t.Fatalf("host=%q port=%d iso=%q", gotHost, gotPort, gotIso)
	}
}

func TestBusyPortIsSkippedNotFatal(t *testing.T) {
	echo := echoTCP(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	good := freeTCP(t)
	m := NewManager(Dialers{}, nil)
	defer m.Close()
	run, skip := m.Apply([]Rule{
		{Proto: "tcp", Listen: busy.Addr().String(), Target: echo, Via: "direct"},
		{Proto: "tcp", Listen: good, Target: echo, Via: "direct"},
	})
	if run != 1 || skip != 1 {
		t.Fatalf("занятый порт должен пропускаться, остальные работать: run=%d skip=%d", run, skip)
	}
	if got := ask(t, good); got != "echo:hi" {
		t.Fatal(got)
	}
	// порт освободился: при следующем применении правило подхватывается
	busy.Close()
	run, skip = m.Apply([]Rule{
		{Proto: "tcp", Listen: busy.Addr().String(), Target: echo, Via: "direct"},
		{Proto: "tcp", Listen: good, Target: echo, Via: "direct"},
	})
	if run != 2 || skip != 0 {
		t.Fatalf("после освобождения порта: run=%d skip=%d", run, skip)
	}
}

func TestApplyRemovesRules(t *testing.T) {
	echo := echoTCP(t)
	listen := freeTCP(t)
	m := NewManager(Dialers{}, nil)
	defer m.Close()
	m.Apply([]Rule{{Proto: "tcp", Listen: listen, Target: echo, Via: "direct"}})
	if ask(t, listen) != "echo:hi" {
		t.Fatal("правило не работает")
	}
	if run, _ := m.Apply(nil); run != 0 {
		t.Fatalf("run=%d", run)
	}
	time.Sleep(100 * time.Millisecond)
	if c, err := net.DialTimeout("tcp", listen, 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("порт должен быть закрыт после удаления правила")
	}
}

func TestUDPMapping(t *testing.T) {
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := srv.ReadFrom(b)
			if err != nil {
				return
			}
			srv.WriteTo(append([]byte("echo:"), b[:n]...), a)
		}
	}()
	tmp, _ := net.ListenPacket("udp", "127.0.0.1:0")
	listen := tmp.LocalAddr().String()
	tmp.Close()

	m := NewManager(Dialers{}, nil)
	defer m.Close()
	if run, skip := m.Apply([]Rule{{Proto: "udp", Listen: listen, Target: srv.LocalAddr().String(), Via: "direct"}}); run != 1 || skip != 0 {
		t.Fatalf("run=%d skip=%d", run, skip)
	}
	c, err := net.Dial("udp", listen)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 2; i++ { // два дейтаграмма подряд через один сеанс
		c.SetDeadline(time.Now().Add(3 * time.Second))
		msg := "ping" + strconv.Itoa(i)
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 64)
		n, err := c.Read(b)
		if err != nil || string(b[:n]) != "echo:"+msg {
			t.Fatalf("ответ %q ошибка %v", b[:n], err)
		}
	}
}
