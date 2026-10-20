package tecon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseBasics(t *testing.T) {
	cfg, err := Parse("\ufeff# комментарий\r\nSocksPort 127.0.0.1:9050   # хвост\r\n\r\nLog notice stdout\r\nUpstream direct\r\nupstream socks5://u:pa%23ss@10.0.0.1:1080 # пароль с решёткой\r\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Tor) != 2 || cfg.Tor[0].Name != "SocksPort" || cfg.Tor[0].Value != "127.0.0.1:9050" || cfg.Tor[1].Value != "notice stdout" {
		t.Fatalf("tor: %+v", cfg.Tor)
	}
	if len(cfg.Upstreams) != 2 || cfg.Upstreams[1] != "socks5://u:pa%23ss@10.0.0.1:1080" {
		t.Fatalf("upstreams: %q", cfg.Upstreams)
	}
	if cfg.Tor[0].Line != 2 {
		t.Fatalf("номер строки: %d", cfg.Tor[0].Line)
	}
}

func TestParseErrorsAndWarnings(t *testing.T) {
	if _, err := Parse("Log notice stdout\nUpstream ftp://x:1\n"); err == nil || !strings.Contains(err.Error(), "строка 2") {
		t.Fatalf("ожидалась ошибка со строкой 2: %v", err)
	}
	if _, err := Parse("Upstream\n"); err == nil {
		t.Fatal("Upstream без значения")
	}
	cfg, err := Parse("Socks5Proxy 1.2.3.4:1080\nSocksPort 9050\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 || len(cfg.Tor) != 1 {
		t.Fatalf("Socks5Proxy должен игнорироваться с предупреждением: %+v", cfg)
	}
}

func TestQuotedHashAndValue(t *testing.T) {
	cfg, _ := Parse("DataDirectory \"C:/my #dir/data\"\n")
	v, ok := cfg.Value("datadirectory")
	if !ok || v != "C:/my #dir/data" {
		t.Fatalf("%q %v", v, ok)
	}
	if _, ok := cfg.Value("nosuch"); ok {
		t.Fatal("нет такой директивы")
	}
}

func TestTorText(t *testing.T) {
	cfg, _ := Parse("SocksPort 9050\nUseBridges 1\nHidServAuth\n")
	if got := cfg.TorText(); got != "SocksPort 9050\nUseBridges 1\nHidServAuth\n" {
		t.Fatalf("%q", got)
	}
}

func TestDiffTor(t *testing.T) {
	a, _ := Parse("SocksPort 9050\nBridge a\nBridge b\nLog notice stdout\n")
	b, _ := Parse("SocksPort 9050\nBridge a\nBridge c\nExitNodes {de}\n")
	ch := DiffTor(a.Tor, b.Tor)
	got := map[string]Change{}
	for _, c := range ch {
		got[c.Key] = c
	}
	if len(got) != 3 {
		t.Fatalf("ожидалось 3 изменения (bridge, exitnodes, log): %+v", ch)
	}
	if c := got["bridge"]; len(c.Old) != 2 || len(c.New) != 2 || c.New[1] != "c" {
		t.Fatalf("bridge: %+v", c)
	}
	if c := got["log"]; len(c.New) != 0 || len(c.Old) != 1 {
		t.Fatalf("log должен быть удалён: %+v", c)
	}
	if c := got["exitnodes"]; len(c.Old) != 0 || c.New[0] != "{de}" {
		t.Fatalf("exitnodes: %+v", c)
	}
	if len(DiffTor(a.Tor, a.Tor)) != 0 {
		t.Fatal("одинаковые настройки не должны давать изменений")
	}
}

func put(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("SocksPort 9050\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFindPriority(t *testing.T) {
	exe, cwd := t.TempDir(), t.TempDir()
	if p, _ := Find(exe, cwd); p != "" {
		t.Fatalf("ничего нет, а найдено %q", p)
	}
	cwdCfg := put(t, cwd, "tecon.cfg")
	if p, _ := Find(exe, cwd); p != cwdCfg {
		t.Fatalf("должен найтись файл из рабочей папки: %q", p)
	}
	exeBare := put(t, exe, "tecon")
	p, notes := Find(exe, cwd)
	if p != exeBare {
		t.Fatalf("рядом с программой приоритетнее, даже без расширения: %q", p)
	}
	if len(notes) == 0 || !strings.Contains(notes[0], "игнорируется") {
		t.Fatalf("ожидалось предупреждение об игнорируемом файле: %v", notes)
	}
	exeCfg := put(t, exe, "tecon.cfg")
	p, notes = Find(exe, cwd)
	if p != exeCfg {
		t.Fatalf("tecon.cfg приоритетнее tecon: %q", p)
	}
	if len(notes) < 2 {
		t.Fatalf("ожидались предупреждения об обоих файлах: %v", notes)
	}
}

func TestFindSameDir(t *testing.T) {
	d := t.TempDir()
	want := put(t, d, "tecon.cfg")
	p, notes := Find(d, d)
	if p != want || len(notes) != 0 {
		t.Fatalf("%q %v", p, notes)
	}
}

func TestCreate(t *testing.T) {
	exe, cwd := t.TempDir(), t.TempDir()
	p, err := Create(exe, cwd)
	if err != nil || filepath.Dir(p) != exe || filepath.Base(p) != "tecon.cfg" {
		t.Fatalf("%q %v", p, err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "\r\n") {
		t.Fatal("ожидались переводы строк CRLF")
	}
	if _, err := Parse(string(b)); err != nil {
		t.Fatalf("файл по умолчанию не разбирается: %v", err)
	}
	// каталог рядом с программой недоступен для записи → рабочая папка
	notDir := filepath.Join(t.TempDir(), "file")
	os.WriteFile(notDir, []byte("x"), 0o644)
	p, err = Create(filepath.Join(notDir, "sub"), cwd)
	if err != nil || filepath.Dir(p) != cwd {
		t.Fatalf("запасной вариант: %q %v", p, err)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg, err := Parse(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := cfg.Value("SocksPort"); !ok || v != "127.0.0.1:9050" {
		t.Fatalf("SocksPort по умолчанию: %q", v)
	}
	if len(cfg.Upstreams) != 0 {
		t.Fatal("по умолчанию вышестоящих прокси нет")
	}
	if _, ok := cfg.Value("DataDirectory"); ok {
		t.Fatal("DataDirectory по умолчанию закомментирован")
	}
	if strings.Contains(DefaultConfig(), "\r") {
		t.Fatal("DefaultConfig должен возвращать LF")
	}
}

// README обязан содержать полный пример, совпадающий с файлом по умолчанию.
func TestReadmeExampleMatchesDefault(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(b), "\r\n", "\n")
	const begin, end = "<!-- TECON-EXAMPLE:BEGIN -->", "<!-- TECON-EXAMPLE:END -->"
	i, j := strings.Index(text, begin), strings.Index(text, end)
	if i < 0 || j < i {
		t.Fatal("в README нет блока примера tecon.cfg между маркерами")
	}
	block := strings.TrimSpace(text[i+len(begin) : j])
	block = strings.TrimPrefix(block, "```text\n")
	block = strings.TrimSuffix(block, "\n```")
	if strings.TrimSpace(block) != strings.TrimSpace(DefaultConfig()) {
		t.Fatal("пример tecon.cfg в README расходится с internal/tecon/default.cfg")
	}
}
