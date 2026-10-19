#!/usr/bin/env python3
"""Разведка 2: теги и go.mod у obfs4/lyrebird/webtunnel (через API GitLab) и сигнатуры нужных функций."""
import json
import re
import urllib.parse
import urllib.request

PROJECTS = [
    ("https://gitlab.com", "yawning/obfs4"),
    ("https://gitlab.torproject.org", "tpo/anti-censorship/pluggable-transports/lyrebird"),
    ("https://gitlab.torproject.org", "tpo/anti-censorship/pluggable-transports/webtunnel"),
]
out = []


def get(url):
    return urllib.request.urlopen(url, timeout=40).read().decode()


def api(host, proj, path):
    return host + "/api/v4/projects/" + urllib.parse.quote(proj, safe="") + path


def raw(host, proj, path, ref):
    return get(api(host, proj, "/repository/files/" + urllib.parse.quote(path, safe="") + "/raw?ref=" + urllib.parse.quote(ref, safe="")))


for host, proj in PROJECTS:
    out.append("== " + proj)
    try:
        tags = json.loads(get(api(host, proj, "/repository/tags?per_page=12")))
    except Exception as e:  # noqa: BLE001
        out.append("  ОШИБКА тегов: %s" % e)
        continue
    for t in tags:
        try:
            mod = raw(host, proj, "go.mod", t["name"])
            go = re.search(r"^go\s+(\S+)", mod, re.M)
            tc = re.search(r"^toolchain\s+(\S+)", mod, re.M)
            first = re.search(r"^module\s+(\S+)", mod, re.M)
            desc = "go %s%s module=%s" % (go.group(1) if go else "?", (" tc " + tc.group(1)) if tc else "", first.group(1) if first else "?")
        except Exception as e:  # noqa: BLE001
            desc = "go.mod: ошибка %s" % e
        out.append("  %s %s (%s) %s" % (t["name"], t["commit"]["id"][:12], t["commit"]["created_at"][:10], desc))
    # структура репозитория
    for sub in ("", "transports", "transport", "main/client"):
        try:
            tree = json.loads(get(api(host, proj, "/repository/tree?per_page=100&path=" + urllib.parse.quote(sub, safe=""))))
            out.append("  tree[%s]: %s" % (sub or "/", " ".join(x["name"] + ("/" if x["type"] == "tree" else "") for x in tree)))
        except Exception:  # noqa: BLE001
            pass

SIGS = [
    ("https://gitlab.torproject.org", "tpo/anti-censorship/pluggable-transports/lyrebird", "transports/transports.go"),
    ("https://gitlab.torproject.org", "tpo/anti-censorship/pluggable-transports/lyrebird", "transports/base/base.go"),
    ("https://gitlab.torproject.org", "tpo/anti-censorship/pluggable-transports/webtunnel", "main/client/webtunnel.go"),
]
for host, proj, path in SIGS:
    out.append("== %s:%s (func/type/interface строки)" % (proj.split("/")[-1], path))
    try:
        txt = raw(host, proj, path, "main")
        for l in txt.splitlines():
            if re.match(r"^(func|type)\s", l) or re.match(r"^\t[A-Z]\w*\(.*\)", l) or l.startswith("import") or re.match(r'^\t"', l) and "tpo" in l:
                out.append("  " + l.strip()[:160])
    except Exception as e:  # noqa: BLE001
        out.append("  ОШИБКА: %s" % e)

text = "\n".join(out)
print(text)
print("::notice title=dep-survey2::" + text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"))
