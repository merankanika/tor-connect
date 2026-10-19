// Package ptargs разбирает параметры подключаемых транспортов (obfs4, webtunnel и др.),
// которые Tor передаёт в полях логина и пароля SOCKS5 (спецификация pluggable transports).
package ptargs

import (
	"errors"
	"strings"
)

// Args — параметры: ключ → список значений.
type Args map[string][]string

// FromSocks собирает строку параметров из логина и пароля SOCKS5 и разбирает её.
// Если пароль состоит из одного нулевого байта, параметры целиком в логине.
func FromSocks(user, pass string) (Args, error) {
	s := user
	if !(len(pass) == 1 && pass[0] == 0) {
		s += pass
	}
	s = strings.TrimRight(s, "\x00")
	return Parse(s)
}

// Parse разбирает «k=v;k2=v2» с экранированием обратной косой чертой символов \ ; =.
func Parse(s string) (Args, error) {
	args := Args{}
	if s == "" {
		return args, nil
	}
	var key, cur []byte
	haveKey := false
	flush := func() error {
		if !haveKey {
			if len(cur) == 0 {
				return nil
			}
			return errors.New("ptargs: параметр без значения")
		}
		args[string(key)] = append(args[string(key)], string(cur))
		key, cur, haveKey = nil, nil, false
		return nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			i++
			if i >= len(s) {
				return nil, errors.New("ptargs: обрыв экранирования")
			}
			cur = append(cur, s[i])
		case c == '=' && !haveKey:
			key, cur, haveKey = cur, nil, true
		case c == ';':
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			cur = append(cur, c)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return args, nil
}

// Get возвращает первое значение параметра.
func (a Args) Get(k string) (string, bool) {
	v, ok := a[k]
	if !ok || len(v) == 0 {
		return "", false
	}
	return v[0], true
}
