package ptargs

import "testing"

func TestParse(t *testing.T) {
	a, err := Parse(`cert=ab+c/d;iat-mode=0`)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := a.Get("cert"); v != "ab+c/d" {
		t.Fatalf("cert=%q", v)
	}
	if v, _ := a.Get("iat-mode"); v != "0" {
		t.Fatalf("iat=%q", v)
	}
}

func TestParseEscapes(t *testing.T) {
	a, err := Parse(`url=https://x/a\;b\=c\\d;ver=0.0.1`)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := a.Get("url"); v != `https://x/a;b=c\d` {
		t.Fatalf("url=%q", v)
	}
	if v, _ := a.Get("ver"); v != "0.0.1" {
		t.Fatalf("ver=%q", v)
	}
}

func TestParseEmptyAndErrors(t *testing.T) {
	if a, err := Parse(""); err != nil || len(a) != 0 {
		t.Fatal("пустая строка")
	}
	if _, err := Parse("novalue"); err == nil {
		t.Fatal("ожидалась ошибка: параметр без значения")
	}
	if _, err := Parse(`a=b\`); err == nil {
		t.Fatal("ожидалась ошибка: обрыв экранирования")
	}
}

func TestFromSocks(t *testing.T) {
	a, err := FromSocks("cert=XYZ;iat-mode=1", "\x00")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := a.Get("cert"); v != "XYZ" {
		t.Fatal("cert")
	}
	// длинные параметры: хвост в поле пароля
	a, err = FromSocks("cert=AAAA", "BBBB;iat-mode=2")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := a.Get("cert"); v != "AAAABBBB" {
		t.Fatalf("cert=%q", v)
	}
	if v, _ := a.Get("iat-mode"); v != "2" {
		t.Fatal("iat-mode")
	}
}
