package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func has(args []string, want ...string) bool {
	for i := range args {
		if i+len(want) > len(args) {
			return false
		}
		ok := true
		for j := range want {
			if args[i+j] != want[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestVersionPassthrough(t *testing.T) {
	dir := t.TempDir()
	r, err := Resolve([]string{"x.exe", "--version"}, dir)
	if err != nil || len(r.Args) != 2 || r.Args[1] != "--version" {
		t.Fatalf("passthrough: %v %v", r.Args, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "torrc.txt")); !os.IsNotExist(err) {
		t.Fatal("--version не должен создавать файлы")
	}
}

func TestNoArgsCreatesDefaults(t *testing.T) {
	dir := t.TempDir()
	r, err := Resolve([]string{"x.exe"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	torrc := filepath.Join(dir, "torrc.txt")
	b, err := os.ReadFile(torrc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "SocksPort 127.0.0.1:9050\r\n") {
		t.Fatalf("нет CRLF/параметров по умолчанию: %q", b[:80])
	}
	if !has(r.Args, "-f", torrc) || !has(r.Args, "--DataDirectory", filepath.Join(dir, "data")) {
		t.Fatalf("args: %v", r.Args)
	}
	if st, err := os.Stat(filepath.Join(dir, "data")); err != nil || !st.IsDir() {
		t.Fatal("каталог data не создан")
	}
}

func TestDefaultTorrcDoesNotSetDataDirectory(t *testing.T) {
	// В файле по умолчанию DataDirectory закомментирован, значит должен применяться каталог рядом с программой.
	dir := t.TempDir()
	p := filepath.Join(dir, "torrc.txt")
	if err := os.WriteFile(p, []byte(strings.ReplaceAll(DefaultTorrc, "\n", "\r\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, err := torrcHasDataDirectory(p)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestBareFileArgument(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "my.txt")
	r, err := Resolve([]string{"x.exe", p, "--Log", "notice stdout"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !has(r.Args, "-f", p) || !has(r.Args, "--Log", "notice stdout") {
		t.Fatalf("args: %v", r.Args)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("torrc по умолчанию не создан по указанному пути")
	}
}

func TestExplicitFlagAndDataDirInTorrc(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.txt")
	if err := os.WriteFile(p, []byte("SocksPort 1234\nDataDirectory C:\\tortest\\data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Resolve([]string{"x.exe", "-f", p}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Args {
		if strings.EqualFold(a, "--DataDirectory") {
			t.Fatalf("DataDirectory из torrc нельзя переопределять: %v", r.Args)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Fatal("лишний каталог data создан")
	}
	b, _ := os.ReadFile(p)
	if string(b) != "SocksPort 1234\nDataDirectory C:\\tortest\\data\n" {
		t.Fatal("существующий torrc изменён")
	}
}

func TestDataDirectoryOnCommandLine(t *testing.T) {
	dir := t.TempDir()
	r, err := Resolve([]string{"x.exe", "--datadirectory", "D:\\x"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range r.Args {
		if strings.EqualFold(a, "--DataDirectory") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("ожидался один --DataDirectory: %v", r.Args)
	}
}

func TestMissingFileAfterFlag(t *testing.T) {
	if _, err := Resolve([]string{"x.exe", "-f"}, t.TempDir()); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}
