package upstream

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/merankanika/tor-connect/internal/socks5"
)

// Serve принимает локальные SOCKS5-подключения (без авторизации) и пересылает их через Dialer.
// Именно к этому адресу подключается Tor как к своему вышестоящему прокси (Socks5Proxy).
// Работает, пока не закрыт ln или не отменён ctx.
func Serve(ctx context.Context, ln net.Listener, d *Dialer) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go handle(ctx, c, d)
	}
}

func handle(ctx context.Context, c net.Conn, d *Dialer) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	req, err := socks5.ReadRequest(c, false)
	if err != nil {
		return
	}
	if req.Cmd != socks5.CmdConnect {
		_ = socks5.Reply(c, socks5.ReplyCommandUnsupported)
		return
	}
	up, err := d.DialContext(ctx, "tcp", req.Addr())
	if err != nil {
		_ = socks5.Reply(c, socks5.ReplyHostUnreachable)
		return
	}
	defer up.Close()
	if socks5.Reply(c, socks5.ReplyOK) != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	Pipe(c, up)
}

// Pipe копирует данные в обе стороны, пока одна из сторон не закроется.
func Pipe(a, b net.Conn) {
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
