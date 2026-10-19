// Package socks5 — минимальная серверная часть SOCKS5 (RFC 1928) с необязательной
// авторизацией по логину и паролю (RFC 1929). Нужна для двух задач:
//   - локальный «маршрутизатор» вышестоящих прокси, к которому подключается Tor;
//   - приём подключений Tor к встроенным транспортам (obfs4 и др.), где параметры моста
//     передаются в полях логина и пароля.
package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Коды ответа.
const (
	ReplyOK                 = 0x00
	ReplyGeneralFailure     = 0x01
	ReplyHostUnreachable    = 0x04
	ReplyConnRefused        = 0x05
	ReplyCommandUnsupported = 0x07
	ReplyAddrUnsupported    = 0x08
)

// CmdConnect — команда CONNECT.
const CmdConnect = 0x01

// Request — разобранный запрос клиента.
type Request struct {
	Cmd     byte
	Host    string // доменное имя или текстовый IP
	Port    int
	HasAuth bool
	User    string
	Pass    string
}

// Addr возвращает адрес в виде host:port (IPv6 в скобках).
func (r *Request) Addr() string { return net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) }

// ReadRequest выполняет рукопожатие и читает запрос. Если offerUserPass истинно и клиент
// предлагает логин/пароль, выбирается он (чтобы получить параметры транспорта); иначе — без авторизации.
func ReadRequest(c io.ReadWriter, offerUserPass bool) (*Request, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 5 {
		return nil, fmt.Errorf("socks5: неподдерживаемая версия %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return nil, err
	}
	hasNone, hasUP := false, false
	for _, m := range methods {
		switch m {
		case 0x00:
			hasNone = true
		case 0x02:
			hasUP = true
		}
	}
	req := &Request{}
	switch {
	case offerUserPass && hasUP:
		if _, err := c.Write([]byte{5, 0x02}); err != nil {
			return nil, err
		}
		u, p, err := readUserPass(c)
		if err != nil {
			return nil, err
		}
		req.HasAuth, req.User, req.Pass = true, u, p
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return nil, err
		}
	case hasNone:
		if _, err := c.Write([]byte{5, 0x00}); err != nil {
			return nil, err
		}
	default:
		_, _ = c.Write([]byte{5, 0xFF})
		return nil, errors.New("socks5: нет подходящего метода авторизации")
	}

	var rh [4]byte
	if _, err := io.ReadFull(c, rh[:]); err != nil {
		return nil, err
	}
	if rh[0] != 5 {
		return nil, fmt.Errorf("socks5: неверная версия в запросе: %d", rh[0])
	}
	req.Cmd = rh[1]
	switch rh[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return nil, err
		}
		req.Host = net.IP(b[:]).String()
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(c, b[:]); err != nil {
			return nil, err
		}
		req.Host = net.IP(b[:]).String()
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return nil, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return nil, err
		}
		req.Host = string(b)
	default:
		_ = Reply(c, ReplyAddrUnsupported)
		return nil, fmt.Errorf("socks5: неподдерживаемый тип адреса %d", rh[3])
	}
	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return nil, err
	}
	req.Port = int(pb[0])<<8 | int(pb[1])
	return req, nil
}

func readUserPass(c io.Reader) (user, pass string, err error) {
	var v [2]byte
	if _, err = io.ReadFull(c, v[:]); err != nil {
		return
	}
	if v[0] != 1 {
		return "", "", fmt.Errorf("socks5: неверная версия авторизации %d", v[0])
	}
	u := make([]byte, int(v[1]))
	if _, err = io.ReadFull(c, u); err != nil {
		return
	}
	var pl [1]byte
	if _, err = io.ReadFull(c, pl[:]); err != nil {
		return
	}
	p := make([]byte, int(pl[0]))
	if _, err = io.ReadFull(c, p); err != nil {
		return
	}
	return string(u), string(p), nil
}

// Reply отправляет ответ с адресом привязки 0.0.0.0:0.
func Reply(c io.Writer, code byte) error {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

// ClientHandshake выполняет клиентскую часть SOCKS5 CONNECT через уже установленное соединение c.
// Если user не пуст, предлагается авторизация по логину и паролю.
func ClientHandshake(c io.ReadWriter, host string, port int, user, pass string) error {
	methods := []byte{0x00}
	if user != "" {
		methods = []byte{0x00, 0x02}
	}
	if _, err := c.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil {
		return err
	}
	if sel[0] != 5 {
		return fmt.Errorf("socks5: сервер ответил версией %d", sel[0])
	}
	switch sel[1] {
	case 0x00:
	case 0x02:
		if user == "" || len(user) > 255 || len(pass) > 255 {
			return errors.New("socks5: неверные логин или пароль для авторизации")
		}
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		if _, err := c.Write(msg); err != nil {
			return err
		}
		var ar [2]byte
		if _, err := io.ReadFull(c, ar[:]); err != nil {
			return err
		}
		if ar[1] != 0 {
			return errors.New("socks5: авторизация отклонена")
		}
	default:
		return errors.New("socks5: сервер не принял методы авторизации")
	}

	if len(host) > 255 {
		return errors.New("socks5: слишком длинное имя узла")
	}
	req := []byte{5, CmdConnect, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rh [4]byte
	if _, err := io.ReadFull(c, rh[:]); err != nil {
		return err
	}
	if rh[1] != ReplyOK {
		return fmt.Errorf("socks5: сервер вернул код %d", rh[1])
	}
	var skip int
	switch rh[3] {
	case 0x01:
		skip = 4 + 2
	case 0x04:
		skip = 16 + 2
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	default:
		return fmt.Errorf("socks5: неизвестный тип адреса в ответе: %d", rh[3])
	}
	_, err := io.CopyN(io.Discard, c, int64(skip))
	return err
}
