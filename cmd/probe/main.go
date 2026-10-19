// probe — пробная программа: запускает Tor, встроенный в этот же процесс (через tor_api.h).
// Никаких дочерних процессов. Все аргументы командной строки передаются Tor как есть.
//
//	probe-win64.exe              (без аргументов: torrc.txt рядом с программой, создаётся при отсутствии)
//	probe-win64.exe torrc.txt    (имя файла можно без -f)
//	probe-win64.exe -f torrc.txt
//	probe-win64.exe --version
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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"github.com/merankanika/tor-connect/internal/cli"
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
