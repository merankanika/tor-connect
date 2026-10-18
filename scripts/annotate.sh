#!/usr/bin/env bash
# annotate.sh <заголовок> <файл...> — печатает ::error:: с хвостом/ошибками логов (для чтения через API Actions)
title="$1"; shift
body="$( { for f in "$@"; do [ -f "$f" ] || continue; echo "### $f (errors)"; grep -n -i -E 'error|fatal|cannot|undefined|not found|failed|multiple definition' "$f" | head -n 60; echo "### $f (tail)"; tail -n 40 "$f"; done; } \
  | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-400 | head -c 60000 )"
body="${body//'%'/'%25'}"; body="${body//$'\r'/'%0D'}"; body="${body//$'\n'/'%0A'}"
echo "::error title=${title}::${body}"
