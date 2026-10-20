// tor-connect — Tor, встроенный в этот же процесс (через tor_api.h).
// Никаких дочерних процессов. Все аргументы командной строки передаются Tor как есть.
//
//	tor-connect.exe                 (файл настроек tecon.cfg / tecon ищется и создаётся автоматически)
//	tor-connect.exe -f мой.cfg      (явный файл настроек; имя можно и без -f)
//	tor-connect.exe -upstream direct -upstream socks5://user:pass@host:1080
//	tor-connect.exe --version
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
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"github.com/merankanika/tor-connect/internal/app"
)

func init() {
	// Tor не рассчитан на миграцию между потоками ОС — держим его на главном потоке.
	runtime.LockOSThread()
}

// runTor запускает Tor в этом же процессе и возвращает код завершения.
func runTor(args []string) int {
	n := len(args)
	size := C.size_t(uintptr(n+1) * unsafe.Sizeof(uintptr(0)))
	argv := (**C.char)(C.malloc(size))
	items := unsafe.Slice(argv, n+1)
	for i, a := range args {
		items[i] = C.CString(a)
	}
	items[n] = nil
	return int(C.run_tor(C.int(n), argv))
}

func main() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "не удалось определить путь к программе:", err)
		os.Exit(2)
	}
	exeDir := filepath.Dir(exe)
	cwd, _ := os.Getwd()

	opts, err := app.ParseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(2)
	}
	if opts.Passthrough {
		os.Exit(runTor(append([]string{os.Args[0]}, opts.TorArgs...)))
	}

	logf := func(format string, a ...any) {
		fmt.Fprintf(os.Stderr, "tor-connect: "+format+"\n", a...)
	}
	sess, err := app.Prepare(opts, exeDir, cwd, logf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(2)
	}
	for _, n := range sess.Notes {
		logf("%s", n)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := sess.StartControl(ctx, 90*time.Second); err != nil {
			if ctx.Err() == nil {
				logf("%v; изменения настроек на лету применяться не будут", err)
			}
			return
		}
		logf("слежу за файлом настроек, изменения применяются на лету")
		sess.Watch(ctx)
	}()

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		logf("завершаю работу (повторное нажатие Ctrl+C завершит принудительно)")
		if !sess.Shutdown() {
			os.Exit(130)
		}
		select {
		case <-sig:
			os.Exit(130)
		case <-time.After(15 * time.Second):
			os.Exit(1)
		}
	}()

	rc := runTor(append([]string{os.Args[0]}, sess.TorArgs...))
	cancel()
	sess.Close()
	os.Exit(rc)
}
