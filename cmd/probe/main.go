// probe — пробная программа: запускает Tor, встроенный в этот же процесс (через tor_api.h).
// Никаких дочерних процессов. Все аргументы командной строки передаются Tor как есть.
//
//	probe-win64.exe --version
//	probe-win64.exe -f torrc.txt
package main

/*
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
	"runtime"
	"unsafe"
)

func init() {
	// Tor не рассчитан на миграцию между потоками ОС — держим его на главном потоке.
	runtime.LockOSThread()
}

func main() {
	args := os.Args
	if len(args) == 1 {
		fmt.Fprintln(os.Stderr, "tor-connect probe: встроенный Tor в одном процессе")
		fmt.Fprintln(os.Stderr, "использование: probe-win64.exe --version | -f torrc.txt")
		args = append(args, "--version")
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
