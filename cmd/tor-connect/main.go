// tor-connect — Tor, встроенный в этот же процесс (через tor_api.h).
// Никаких дочерних процессов. Все аргументы командной строки передаются Tor как есть.
//
//	tor-connect.exe              (без аргументов: torrc.txt рядом с программой, создаётся при отсутствии)
//	tor-connect.exe torrc.txt    (имя файла можно без -f)
//	tor-connect.exe -f torrc.txt
//	tor-connect.exe --version
//	tor-connect.exe -upstream direct -upstream socks5://user:pass@host:1080 -upstream http://host:8080
package main

/*
#include <winsock2.h>
#include <stdlib.h>
#include "tor_api.h"

static int run_tor(int argc, char **argv) {
	tor_main_configuration_t *cfg = tor_main_configuration_new();
	if (cfg == NULL) {
		return -1;
	}
	if (tor_main_configuration_set_command_line(cfg, argc, argv) != 0) {
		tor_main_configuration_free(cfg);
		return -2;
	}
	int rv = tor_run_main(cfg);
	tor_main_configuration_free(cfg);
	return rv;
}
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/merankanika/tor-connect/internal/cli"
	"github.com/merankanika/tor-connect/internal/upstream"
)

func init() {
	// Tor не рассчитан на миграцию между потоками ОС — держим его на главном потоке.
	runtime.LockOSThread()
}

func main() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "не удалось определить путь к программе:", err)
		os.Exit(2)
	}
	res, err := cli.Resolve(os.Args, filepath.Dir(exe))
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(2)
	}
	for _, n := range res.Notes {
		fmt.Fprintln(os.Stderr, "tor-connect:", n)
	}

	args := res.Args
	if len(res.Upstreams) > 0 {
		specs, err := upstream.ParseSpecs(res.Upstreams)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ошибка:", err)
			os.Exit(2)
		}
		d := upstream.New(specs, upstream.Options{Logf: func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, "tor-connect: "+format+"\n", a...)
		}})
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Fprintln(os.Stderr, "ошибка: не удалось открыть локальный порт для вышестоящих прокси:", err)
			os.Exit(2)
		}
		go func() { _ = upstream.Serve(context.Background(), ln, d) }()
		names := make([]string, len(specs))
		for i, s := range specs {
			names[i] = s.String()
		}
		fmt.Fprintln(os.Stderr, "tor-connect: вышестоящие прокси по порядку:", strings.Join(names, ", "))
		args = append(args, "--Socks5Proxy", ln.Addr().String())
	}
	n := len(args)
	size := C.size_t(uintptr(n+1) * unsafe.Sizeof(uintptr(0)))
	argv := (**C.char)(C.malloc(size))
	items := unsafe.Slice(argv, n+1)
	for i, a := range args {
		items[i] = C.CString(a)
	}
	items[n] = nil

	rc := C.run_tor(C.int(n), argv)
	os.Exit(int(rc))
}
