#!/usr/bin/env python3
"""Разведка: какие версии библиотек транспортов совместимы с Go 1.20 (нужен для Windows 7).
Читает go.mod каждой версии с proxy.golang.org и печатает директиву go. Результат — в аннотацию Actions."""
import re
import sys
import urllib.request

MODS = [
    "gitlab.com/yawning/obfs4.git",
    "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird",
    "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel",
    "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib",
    "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2",
]
PROXY = "https://proxy.golang.org/"


def get(url):
    return urllib.request.urlopen(url, timeout=40).read().decode()


def esc(m):
    return re.sub(r"[A-Z]", lambda x: "!" + x.group(0).lower(), m)


def key(v):
    m = re.match(r"v(\d+)\.(\d+)\.(\d+)$", v)
    return tuple(int(x) for x in m.groups()) if m else None


lines = []
for m in MODS:
    lines.append("== " + m)
    try:
        vs = [v for v in get(PROXY + esc(m) + "/@v/list").split() if key(v)]
    except Exception as e:  # noqa: BLE001
        lines.append("  ОШИБКА списка версий: %s" % e)
        continue
    vs.sort(key=key, reverse=True)
    if not vs:
        lines.append("  (нет релизных версий в прокси)")
    for v in vs[:10]:
        try:
            mod = get(PROXY + esc(m) + "/@v/" + v + ".mod")
        except Exception as e:  # noqa: BLE001
            lines.append("  %s: ОШИБКА %s" % (v, e))
            continue
        go = re.search(r"^go\s+(\S+)", mod, re.M)
        tc = re.search(r"^toolchain\s+(\S+)", mod, re.M)
        extra = ""
        for dep in ("gitlab.com/yawning/obfs4.git", "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel",
                    "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib", "golang.org/x/crypto", "github.com/pion/webrtc/v3", "github.com/pion/webrtc/v4"):
            d = re.search(r"^\s*" + re.escape(dep) + r"\s+(\S+)", mod, re.M)
            if d and dep != m:
                extra += " %s=%s" % (dep.split("/")[-1] if "x/crypto" not in dep else "x/crypto", d.group(1))
        lines.append("  %s: go %s%s%s" % (v, go.group(1) if go else "?", (" toolchain " + tc.group(1)) if tc else "", extra))

text = "\n".join(lines)
print(text)
body = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
print("::notice title=dep-survey (go directives)::" + body)
