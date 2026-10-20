// Package tcontrol — минимальный клиент управляющего протокола Tor (control-spec):
// аутентификация по cookie, SETCONF, GETINFO, SIGNAL. Нужен, чтобы менять настройки
// работающего Tor «на лету» и корректно его завершать.
package tcontrol

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Client — соединение с управляющим портом Tor.
type Client struct {
	c  net.Conn
	br *bufio.Reader
	mu sync.Mutex
}

// Dial подключается к управляющему порту.
func Dial(addr string, timeout time.Duration) (*Client, error) {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	return &Client{c: c, br: bufio.NewReader(c)}, nil
}

// Close закрывает соединение.
func (c *Client) Close() error { return c.c.Close() }

// Cmd отправляет команду и возвращает строки ответа (без кодов). Ошибка — если код не 250.
func (c *Client) Cmd(cmd string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if strings.ContainsAny(cmd, "\r\n") {
		return nil, errors.New("tcontrol: перевод строки в команде")
	}
	_ = c.c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.c.Write([]byte(cmd + "\r\n")); err != nil {
		return nil, err
	}
	return c.readReply()
}

func (c *Client) readReply() ([]string, error) {
	var lines []string
	bad := ""
	for {
		l, err := c.br.ReadString('\n')
		if err != nil {
			return lines, err
		}
		l = strings.TrimRight(l, "\r\n")
		if len(l) < 4 {
			return lines, fmt.Errorf("tcontrol: некорректный ответ %q", l)
		}
		code, sep, text := l[:3], l[3], l[4:]
		if code != "250" && bad == "" {
			bad = code + " " + text
		}
		switch sep {
		case '+':
			var data []string
			for {
				dl, err := c.br.ReadString('\n')
				if err != nil {
					return lines, err
				}
				dl = strings.TrimRight(dl, "\r\n")
				if dl == "." {
					break
				}
				if strings.HasPrefix(dl, "..") {
					dl = dl[1:]
				}
				data = append(data, dl)
			}
			lines = append(lines, text+"\n"+strings.Join(data, "\n"))
		case '-':
			lines = append(lines, text)
		case ' ':
			lines = append(lines, text)
			if bad != "" {
				return lines, fmt.Errorf("tor: %s", bad)
			}
			return lines, nil
		default:
			return lines, fmt.Errorf("tcontrol: некорректный разделитель в %q", l)
		}
	}
}

// AuthenticateCookie проходит аутентификацию содержимым cookie-файла.
func (c *Client) AuthenticateCookie(cookie []byte) error {
	_, err := c.Cmd("AUTHENTICATE " + hex.EncodeToString(cookie))
	return err
}

// Quote оформляет строку как QuotedString протокола.
func Quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
	return `"` + r.Replace(s) + `"`
}

// SetConf устанавливает значения опции (несколько значений — многозначная опция).
// Без значений сбрасывает опцию к значению по умолчанию.
func (c *Client) SetConf(name string, values ...string) error {
	cmd := "SETCONF " + name
	if len(values) > 0 {
		cmd = "SETCONF"
		for _, v := range values {
			cmd += " " + name + "=" + Quote(v)
		}
	}
	_, err := c.Cmd(cmd)
	return err
}

// GetInfo возвращает значение ключа GETINFO.
func (c *Client) GetInfo(key string) (string, error) {
	lines, err := c.Cmd("GETINFO " + key)
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if strings.HasPrefix(l, key+"=") {
			return strings.TrimPrefix(l, key+"="), nil
		}
	}
	return "", fmt.Errorf("tcontrol: нет значения для %s", key)
}

// Signal отправляет сигнал (SHUTDOWN, HALT, RELOAD, NEWNYM и др.).
func (c *Client) Signal(sig string) error {
	_, err := c.Cmd("SIGNAL " + sig)
	return err
}

// ReadPortFile читает файл ControlPortWriteToFile («PORT=127.0.0.1:12345») и возвращает адрес.
func ReadPortFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "PORT=") {
			return strings.TrimPrefix(l, "PORT="), nil
		}
	}
	return "", fmt.Errorf("tcontrol: в %s нет строки PORT=", path)
}
