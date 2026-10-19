// Package cli готовит командную строку для встроенного Tor:
// создаёт torrc.txt с параметрами по умолчанию, если его нет, и задаёт каталог данных.
// Пакет не зависит от cgo и тестируется на любой платформе.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultTorrc — содержимое torrc.txt, создаваемого при первом запуске (строки разделены CRLF для Блокнота Windows).
const DefaultTorrc = `# tor-connect: конфигурация по умолчанию (создана автоматически).
# Строки, начинающиеся с #, — комментарии. Уберите # у нужной строки, чтобы включить параметр.

# Локальный прокси SOCKS5 (только для этого компьютера).
SocksPort 127.0.0.1:9050

# Журнал выводится в окно программы.
Log notice stdout

# Каталог данных Tor. Если строка закомментирована, используется папка data рядом с программой.
#DataDirectory D:\tor\data

# --- Страна выхода (нужны файлы GeoIP; позже их будет скачивать команда -geo-update) ---
#ExitNodes {de},{nl}
#StrictNodes 1

# --- Если Tor блокируют: мосты ---
# Обычный мост без транспорта (формат: IP:порт ОТПЕЧАТОК). Мосты obfs4/webtunnel/Snowflake появятся позже.
#UseBridges 1
#Bridge 203.0.113.10:443 0123456789ABCDEF0123456789ABCDEF01234567

# --- Прочее ---
# Прокси доступен и другим устройствам в сети (без пароля — только в доверенной сети!):
#SocksPort 0.0.0.0:9050
#SocksPolicy accept 192.168.0.0/16
#SocksPolicy reject *
`

// Result — подготовленная командная строка для Tor.
type Result struct {
	Args      []string // полный argv для Tor, включая argv[0]
	Notes     []string // сообщения пользователю
	TorrcPath string   // путь к используемому torrc ("" в режиме --version/--help)
}

// passthrough — команды Tor, которым конфигурация не нужна.
var passthrough = map[string]bool{
	"--version": true, "-version": true, "--help": true, "-h": true, "-help": true,
	"--hash-password": true, "--list-torrc-options": true, "--list-deprecated-options": true,
}

func isTorrcFlag(a string) bool { return a == "-f" || a == "--torrc-file" }

// Resolve разбирает аргументы программы (args[0] — имя exe) и каталог программы exeDir.
func Resolve(args []string, exeDir string) (Result, error) {
	if len(args) == 0 {
		return Result{}, fmt.Errorf("пустой список аргументов")
	}
	argv0, rest := args[0], append([]string(nil), args[1:]...)
	var res Result

	for _, a := range rest {
		if passthrough[strings.ToLower(a)] {
			res.Args = append([]string{argv0}, rest...)
			return res, nil
		}
	}

	// 1. Определяем путь к torrc.
	torrc := ""
	var out []string
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		// голое имя файла: probe.exe torrc.txt  ==  probe.exe -f torrc.txt
		torrc = rest[0]
		rest = rest[1:]
		res.Notes = append(res.Notes, "первый аргумент принят как файл конфигурации (-f можно не указывать)")
	}
	for i := 0; i < len(rest); i++ {
		if isTorrcFlag(rest[i]) {
			if i+1 >= len(rest) {
				return Result{}, fmt.Errorf("после %s не указан файл", rest[i])
			}
			torrc = rest[i+1]
			i++
			continue
		}
		out = append(out, rest[i])
	}
	if torrc == "" {
		torrc = filepath.Join(exeDir, "torrc.txt")
	}
	if abs, err := filepath.Abs(torrc); err == nil {
		torrc = abs
	}

	// 2. Создаём torrc с параметрами по умолчанию, если файла нет.
	if _, err := os.Stat(torrc); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(torrc), 0o755); err != nil {
			return Result{}, fmt.Errorf("не удалось создать каталог для %s: %w", torrc, err)
		}
		text := strings.ReplaceAll(DefaultTorrc, "\n", "\r\n")
		if err := os.WriteFile(torrc, []byte(text), 0o644); err != nil {
			return Result{}, fmt.Errorf("не удалось создать %s: %w", torrc, err)
		}
		res.Notes = append(res.Notes, "создан файл конфигурации по умолчанию: "+torrc)
	} else if err != nil {
		return Result{}, fmt.Errorf("не удалось проверить %s: %w", torrc, err)
	}
	res.TorrcPath = torrc

	// 3. Каталог данных: если не задан ни в torrc, ни в командной строке — папка data рядом с программой.
	hasDD := false
	for _, a := range out {
		if strings.EqualFold(a, "--DataDirectory") {
			hasDD = true
		}
	}
	if !hasDD {
		var err error
		if hasDD, err = torrcHasDataDirectory(torrc); err != nil {
			return Result{}, fmt.Errorf("не удалось прочитать %s: %w", torrc, err)
		}
	}
	final := append([]string{argv0, "-f", torrc}, out...)
	if !hasDD {
		dd := filepath.Join(exeDir, "data")
		if err := os.MkdirAll(dd, 0o700); err != nil {
			return Result{}, fmt.Errorf("не удалось создать каталог данных %s: %w", dd, err)
		}
		final = append(final, "--DataDirectory", dd)
		res.Notes = append(res.Notes, "каталог данных (по умолчанию): "+dd)
	}
	res.Args = final
	return res, nil
}

// torrcHasDataDirectory сообщает, есть ли в torrc активная (не закомментированная) строка DataDirectory.
func torrcHasDataDirectory(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], "DataDirectory") {
			return true, nil
		}
	}
	return false, sc.Err()
}
