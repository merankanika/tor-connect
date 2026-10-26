#!/usr/bin/env bash
# Установка пакетов на раннере GitHub: только официальные репозитории Ubuntu (сторонние репозитории раннера
# не опрашиваются) и перебор нескольких зеркал с короткими таймаутами, чтобы сбой одного зеркала не вешал сборку.
# Использование: ci-apt.sh пакет...
set -u
codename="$(. /etc/os-release; echo "$VERSION_CODENAME")"
parts="$(mktemp -d)"
mirrors=("http://archive.ubuntu.com/ubuntu" "http://mirrors.kernel.org/ubuntu" "http://azure.archive.ubuntu.com/ubuntu" "http://mirror.hetzner.com/ubuntu/packages")
opts=(-o Dir::Etc::sourcelist=/dev/null -o "Dir::Etc::sourceparts=$parts" -o Acquire::Retries=2 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)

for m in "${mirrors[@]}"; do
  echo "== зеркало: $m"
  cat > "$parts/ubuntu.sources" <<SRC
Types: deb
URIs: $m
Suites: $codename ${codename}-updates ${codename}-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SRC
  if sudo timeout 120 apt-get "${opts[@]}" update && sudo timeout 420 apt-get "${opts[@]}" install -y --no-install-recommends "$@"; then
    exit 0
  fi
  echo "зеркало $m не сработало, пробую следующее"
done
echo "не удалось установить пакеты ни с одного зеркала"
exit 1
