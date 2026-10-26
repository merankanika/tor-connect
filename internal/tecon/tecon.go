// Package tecon — разбор единого файла настроек tecon.cfg (Tor Extended CONfig):
// обычный torrc, расширенный директивами tor-connect. Директивы tor-connect
// обрабатываются программой, все остальные строки передаются Tor как есть.
package tecon

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/merankanika/tor-connect/internal/portmap"
	"github.com/merankanika/tor-connect/internal/upstream"
)

//go:embed default.cfg
var defaultCfg string

// DefaultConfig возвращает текст файла по умолчанию (переводы строк LF).
func DefaultConfig() string { return strings.ReplaceAll(defaultCfg, "\r\n", "\n") }

// FileNames — имена файла настроек в порядке приоритета.
var FileNames = []string{"tecon.cfg", "tecon"}

// Directive — строка настроек Tor.
type Directive struct {
	Name  string
	Value string
	Line  int
}

// Config — разобранный файл.
type Config struct {
	Upstreams []string       // значения директив Upstream по порядку
	Maps      []portmap.Rule // MapPort и MapPortUDP
	Tor       []Directive    // всё остальное — для Tor
	Warnings  []string
}

// Директивы Tor, которые заменены директивой Upstream.
var replacedByUpstream = map[string]bool{
	"socks5proxy": true, "socks5proxyusername": true, "socks5proxypassword": true,
	"httpsproxy": true, "httpsproxyauthenticator": true,
}

// pathDirectives — директивы Tor со значением-путём: относительные пути считаются от папки файла настроек.
var pathDirectives = map[string]bool{
	"datadirectory": true, "hiddenservicedir": true, "clientonionauthdir": true,
	"geoipfile": true, "geoipv6file": true,
}

// UnquoteValue снимает с значения кавычки в стиле torrc (с обработкой \\, \", \n, \r, \t).
func UnquoteValue(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}
	in := v[1 : len(v)-1]
	var b strings.Builder
	for i := 0; i < len(in); i++ {
		if in[i] == '\\' && i+1 < len(in) {
			i++
			switch in[i] {
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(in[i])
			}
			continue
		}
		b.WriteByte(in[i])
	}
	return b.String()
}

func resolvePath(value, baseDir string) string {
	v := UnquoteValue(value)
	if v == "" || filepath.IsAbs(v) || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "\\") {
		return value
	}
	return `"` + filepath.ToSlash(filepath.Join(baseDir, v)) + `"`
}

// Parse разбирает текст настроек (относительные пути не пересчитываются).
func Parse(text string) (*Config, error) { return ParseBase(text, "") }

// ParseBase разбирает текст настроек; если baseDir не пуст, относительные пути (DataDirectory, HiddenServiceDir и др.)
// считаются от этой папки (обычно это папка файла настроек).
func ParseBase(text, baseDir string) (*Config, error) {
	text = strings.TrimPrefix(text, "\ufeff")
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	cfg := &Config{}
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(stripComment(sc.Text()))
		if line == "" {
			continue
		}
		name, value := splitDirective(line)
		key := strings.ToLower(name)
		switch {
		case key == "upstream":
			if value == "" {
				return nil, fmt.Errorf("строка %d: Upstream без значения", n)
			}
			if _, err := upstream.ParseSpec(value); err != nil {
				return nil, fmt.Errorf("строка %d: Upstream: %w", n, err)
			}
			cfg.Upstreams = append(cfg.Upstreams, value)
		case key == "mapport" || key == "mapportudp":
			proto := "tcp"
			if key == "mapportudp" {
				proto = "udp"
			}
			r, err := portmap.ParseRule(proto, value)
			if err != nil {
				return nil, fmt.Errorf("строка %d: %s: %w", n, name, err)
			}
			cfg.Maps = append(cfg.Maps, r)
		case replacedByUpstream[key]:
			cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("строка %d: %s игнорируется (используйте Upstream)", n, name))
		default:
			if baseDir != "" && pathDirectives[key] && value != "" {
				value = resolvePath(value, baseDir)
			}
			cfg.Tor = append(cfg.Tor, Directive{Name: name, Value: value, Line: n})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// stripComment отрезает комментарий: «#» в начале строки или после пробела вне кавычек.
func stripComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' && (i == 0 || s[i-1] != '\\'):
			inQuote = !inQuote
		case c == '#' && !inQuote && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

func splitDirective(line string) (name, value string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimSpace(line[i+1:])
}

// Value возвращает последнее значение директивы Tor (без внешних кавычек).
func (c *Config) Value(name string) (string, bool) {
	val, ok := "", false
	for _, d := range c.Tor {
		if strings.EqualFold(d.Name, name) {
			val, ok = d.Value, true
		}
	}
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		val = val[1 : len(val)-1]
	}
	return val, ok
}

// Text возвращает директивы в виде torrc.
func Text(ds []Directive) string {
	var b strings.Builder
	for _, d := range ds {
		b.WriteString(d.Name)
		if d.Value != "" {
			b.WriteByte(' ')
			b.WriteString(d.Value)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// TorText возвращает строки для Tor в виде torrc.
func (c *Config) TorText() string { return Text(c.Tor) }

// Change — изменившаяся директива Tor (Name записано так, как в файле; Key — в нижнем регистре).
type Change struct {
	Name string
	Key  string
	Old  []string
	New  []string

	// Group: изменилась семья директив HiddenService*, зависящих от порядка. Tor нужно передать их все сразу.
	Group      bool
	Pairs      []NameValue // новый набор в порядке файла (пусто — службы убраны)
	ResetNames []string    // имена директив семьи в прежних настройках (для сброса)
}

// NameValue — директива «имя значение».
type NameValue struct{ Name, Value string }

const hiddenServicePrefix = "hiddenservice"

type grouped struct {
	order []string
	vals  map[string][]string
	names map[string]string
}

func group(ds []Directive) grouped {
	g := grouped{vals: map[string][]string{}, names: map[string]string{}}
	for _, d := range ds {
		k := strings.ToLower(d.Name)
		if _, ok := g.vals[k]; !ok {
			g.order = append(g.order, k)
			g.names[k] = d.Name
		}
		g.vals[k] = append(g.vals[k], d.Value)
	}
	return g
}

func equal(a, b []string) bool {
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

// DiffTor сравнивает настройки Tor: возвращает директивы, у которых набор значений изменился
// (удалённая директива имеет пустой New).
func DiffTor(oldC, newC []Directive) []Change {
	o, n := group(oldC), group(newC)
	var out []Change
	seen := map[string]bool{}
	for _, k := range append(append([]string{}, n.order...), o.order...) {
		if seen[k] {
			continue
		}
		seen[k] = true
		if equal(o.vals[k], n.vals[k]) {
			continue
		}
		name := n.names[k]
		if name == "" {
			name = o.names[k]
		}
		out = append(out, Change{Name: name, Key: k, Old: o.vals[k], New: n.vals[k]})
	}

	// Директивы HiddenService* связаны порядком (HiddenServiceDir, затем его HiddenServicePort и т.д.):
	// при любом изменении передаём Tor всю семью одной командой.
	var plain []Change
	hsChanged := false
	for _, c := range out {
		if strings.HasPrefix(c.Key, hiddenServicePrefix) {
			hsChanged = true
		} else {
			plain = append(plain, c)
		}
	}
	if hsChanged {
		g := Change{Name: "HiddenService*", Key: "hiddenservice*", Group: true}
		for _, d := range newC {
			if strings.HasPrefix(strings.ToLower(d.Name), hiddenServicePrefix) {
				g.Pairs = append(g.Pairs, NameValue{d.Name, d.Value})
			}
		}
		seenName := map[string]bool{}
		for _, d := range oldC {
			k := strings.ToLower(d.Name)
			if strings.HasPrefix(k, hiddenServicePrefix) && !seenName[k] {
				seenName[k] = true
				g.ResetNames = append(g.ResetNames, d.Name)
			}
		}
		plain = append(plain, g)
	}
	return plain
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}

// Find ищет файл настроек: сначала рядом с программой, затем в рабочей папке.
// Файл рядом с программой приоритетнее и полностью перекрывает файл из рабочей папки.
func Find(exeDir, cwd string) (path string, notes []string) {
	var dirs []string
	dirs = append(dirs, exeDir)
	if cwd != "" && !sameDir(cwd, exeDir) {
		dirs = append(dirs, cwd)
	}
	for _, dir := range dirs {
		var found []string
		for _, n := range FileNames {
			if p := filepath.Join(dir, n); isFile(p) {
				found = append(found, p)
			}
		}
		if len(found) == 0 {
			continue
		}
		if len(found) > 1 {
			notes = append(notes, fmt.Sprintf("в %s найдены оба файла настроек; используется %s, а %s игнорируется", dir, filepath.Base(found[0]), filepath.Base(found[1])))
		}
		if dir == exeDir && len(dirs) > 1 {
			for _, n := range FileNames {
				if p := filepath.Join(cwd, n); isFile(p) {
					notes = append(notes, fmt.Sprintf("файл %s в рабочей папке игнорируется: рядом с программой найден %s", p, found[0]))
					break
				}
			}
		}
		return found[0], notes
	}
	return "", notes
}

func sameDir(a, b string) bool {
	aa, e1 := filepath.Abs(a)
	bb, e2 := filepath.Abs(b)
	return e1 == nil && e2 == nil && strings.EqualFold(filepath.Clean(aa), filepath.Clean(bb))
}

// Write создаёт файл настроек по умолчанию по указанному пути (переводы строк CRLF для Блокнота Windows).
func Write(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.ReplaceAll(DefaultConfig(), "\n", "\r\n")), 0o644)
}

// Create создаёт tecon.cfg по умолчанию рядом с программой, а если там нельзя писать — в рабочей папке.
func Create(exeDir, cwd string) (string, error) {
	var firstErr error
	for _, dir := range []string{exeDir, cwd} {
		if dir == "" {
			continue
		}
		p := filepath.Join(dir, FileNames[0])
		err := Write(p)
		if err == nil {
			return p, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return "", fmt.Errorf("не удалось создать файл настроек: %w", firstErr)
}
