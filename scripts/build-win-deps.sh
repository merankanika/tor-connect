#!/usr/bin/env bash
# Статическая сборка zlib, libevent, OpenSSL и Tor (как библиотеки) для Windows x64.
# Кросс-компиляция mingw-w64 (классическая CRT msvcrt, без UCRT) с целевой Windows 7.
# При сбое этапа в GitHub Actions выводит хвост лога в аннотацию (читается через API).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/versions.env"

WORK="${WORK:-$ROOT/build}"
PREFIX="$WORK/prefix"; SRC="$WORK/src"; DL="$WORK/dl"; LOGDIR="$WORK/logs"
mkdir -p "$PREFIX/lib" "$PREFIX/include" "$SRC" "$DL" "$LOGDIR"

HOST=x86_64-w64-mingw32
export CC="${HOST}-gcc" AR="${HOST}-ar" RANLIB="${HOST}-ranlib" STRIP="${HOST}-strip" WINDRES="${HOST}-windres" RC="${HOST}-windres"
WINFLAGS="-D_WIN32_WINNT=0x0601 -DWINVER=0x0601"
CF="-O2 -pipe ${WINFLAGS}"
J="$(nproc)"

fetch() { curl -fsSL --retry 4 --retry-delay 3 -o "$2" "$1"; }
check() { echo "$2  $1" | sha256sum -c -; }

# stage <имя> <функция> [файл-с-доп.логом]
stage() {
  local name="$1" fn="$2" extra="${3:-}" log="$LOGDIR/$1.log"
  printf '\n===== %s =====\n' "$name"
  set +e
  ( set -euo pipefail; "$fn" ) 2>&1 | tee "$log"
  local rc="${PIPESTATUS[0]}"
  set -e
  if [ "$rc" -ne 0 ]; then
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      local body
      body="$( { echo "### errors"; grep -n -i -E 'error|fatal|cannot|no such file|undefined|not found|failed' "$log" | head -n 40;
                 echo "### tail"; tail -n 50 "$log";
                 if [ -n "$extra" ]; then for f in $extra; do [ -f "$f" ] && { echo "### $f (tail)"; tail -n 60 "$f"; }; done; fi; } \
               | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-300 | head -c 60000 )"
      body="${body//'%'/'%25'}"; body="${body//$'\r'/'%0D'}"; body="${body//$'\n'/'%0A'}"
      echo "::error title=stage ${name} failed (rc=${rc})::${body}"
    fi
    exit "$rc"
  fi
}

# ---------- zlib ----------
do_zlib() {
  fetch "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz" "$DL/zlib.tgz"
  check "$DL/zlib.tgz" "$ZLIB_SHA256"
  tar -C "$SRC" -xf "$DL/zlib.tgz"
  cd "$SRC/zlib-${ZLIB_VERSION}"
  make -f win32/Makefile.gcc PREFIX="${HOST}-" LOC="${CF}" libz.a
  cp libz.a "$PREFIX/lib/"; cp zlib.h zconf.h "$PREFIX/include/"
}

# ---------- libevent ----------
do_libevent() {
  fetch "https://github.com/libevent/libevent/releases/download/release-${LIBEVENT_VERSION}/libevent-${LIBEVENT_VERSION}.tar.gz" "$DL/libevent.tgz"
  check "$DL/libevent.tgz" "$LIBEVENT_SHA256"
  tar -C "$SRC" -xf "$DL/libevent.tgz"
  cd "$SRC/libevent-${LIBEVENT_VERSION}"
  ./configure --host="$HOST" --prefix="$PREFIX" --disable-shared --enable-static \
    --disable-openssl --disable-samples --disable-libevent-regress --disable-debug-mode \
    CFLAGS="${CF}"
  make -j"$J"; make install
}

# ---------- OpenSSL ----------
do_openssl() {
  fetch "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" "$DL/openssl.tgz"
  check "$DL/openssl.tgz" "$OPENSSL_SHA256"
  tar -C "$SRC" -xf "$DL/openssl.tgz"
  cd "$SRC/openssl-${OPENSSL_VERSION}"
  # OpenSSL сам добавляет --cross-compile-prefix к CC/AR/..., поэтому полные имена из окружения убираем
  unset CC AR RANLIB STRIP WINDRES RC
  ./Configure mingw64 no-shared no-tests no-docs no-apps no-module \
    --cross-compile-prefix="${HOST}-" --prefix="$PREFIX" --libdir=lib --openssldir="$PREFIX/ssl" \
    ${WINFLAGS}
  make -j"$J" build_libs
  make install_dev
}

# ---------- Tor ----------
do_tor() {
  local got=0 base
  for base in "https://dist.torproject.org" "https://archive.torproject.org/tor-package-archive"; do
    if fetch "$base/tor-${TOR_VERSION}.tar.gz" "$DL/tor.tgz" && fetch "$base/tor-${TOR_VERSION}.tar.gz.sha256sum" "$DL/tor.sha256sum"; then got=1; break; fi
  done
  [ "$got" = 1 ] || { echo "Не удалось скачать Tor ${TOR_VERSION}"; return 1; }
  local actual published
  actual="$(sha256sum "$DL/tor.tgz" | cut -d' ' -f1)"
  published="$(cut -d' ' -f1 "$DL/tor.sha256sum" | head -n1)"
  echo "Tor sha256 (скачанный):      $actual"
  echo "Tor sha256 (опубликованный): $published"
  [ "$actual" = "$published" ] || { echo "Хэш Tor не совпал с опубликованным"; return 1; }
  if [ -n "${TOR_SHA256:-}" ]; then [ "$actual" = "$TOR_SHA256" ] || { echo "Хэш Tor не совпал с закреплённым"; return 1; }; fi
  tar -C "$SRC" -xf "$DL/tor.tgz"
  cd "$SRC/tor-${TOR_VERSION}"
  ./configure --host="$HOST" --prefix="$PREFIX" \
    --disable-asciidoc --disable-manpage --disable-html-manual --disable-unittests \
    --disable-systemd --disable-seccomp --disable-libscrypt --disable-lzma --disable-zstd \
    --disable-module-relay --disable-module-dirauth \
    --with-libevent-dir="$PREFIX" --with-openssl-dir="$PREFIX" --with-zlib-dir="$PREFIX" \
    CFLAGS="${CF}" CPPFLAGS="-I$PREFIX/include" LDFLAGS="-L$PREFIX/lib" \
    LIBS="-lcrypt32 -lgdi32 -lws2_32 -liphlpapi -luser32 -ladvapi32 -lbcrypt"
  make -j"$J" src/app/tor.exe
  echo "--- собранные статические библиотеки Tor:"; find src -name '*.a' | sort
}

stage zlib     do_zlib
stage libevent do_libevent "$SRC/libevent-${LIBEVENT_VERSION}/config.log"
stage openssl  do_openssl
stage tor      do_tor      "$SRC/tor-${TOR_VERSION}/config.log"

printf '\n===== Готово =====\n'
