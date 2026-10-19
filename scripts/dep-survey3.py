#!/usr/bin/env python3
"""Разведка 3: сигнатуры API lyrebird (0.3.0 и main) и webtunnel — отдельными аннотациями."""
import json
import re
import urllib.parse
import urllib.request

TPO = "https://gitlab.torproject.org"
LYRE = "tpo/anti-censorship/pluggable-transports/lyrebird"
WEB = "tpo/anti-censorship/pluggable-transports/webtunnel"


def get(url):
    return urllib.request.urlopen(url, timeout=40).read().decode()


def api(proj, path):
    return TPO + "/api/v4/projects/" + urllib.parse.quote(proj, safe="") + path


def raw(proj, path, ref):
    return get(api(proj, "/repository/files/" + urllib.parse.quote(path, safe="") + "/raw?ref=" + urllib.parse.quote(ref, safe="")))


def tree(proj, path, ref):
    return json.loads(get(api(proj, "/repository/tree?per_page=100&ref=%s&path=%s" % (urllib.parse.quote(ref, safe=""), urllib.parse.quote(path, safe="")))))


def notice(title, lines):
    text = "\n".join(lines)
    print("== " + title + "\n" + text)
    print("::notice title=%s::%s" % (title, text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")))


def sigs(proj, path, ref):
    out = []
    try:
        txt = raw(proj, path, ref)
    except Exception as e:  # noqa: BLE001
        return ["ОШИБКА: %s" % e]
    in_iface = False
    for l in txt.splitlines():
        if re.match(r"^type\s+\w+\s+interface", l):
            in_iface = True
        if re.match(r"^(func|type|var|const)\s", l) or in_iface or (re.match(r'^\s+"', l) and "tpo" in l or "yawning" in l):
            out.append(l.rstrip()[:170])
        if in_iface and l.startswith("}"):
            in_iface = False
    return out[:80]


for ref in ("lyrebird-0.3.0", "main"):
    t = []
    for sub in ("transports", "transports/obfs4", "transports/webtunnel", "common", "common/pt_extras"):
        try:
            t.append("tree[%s]: %s" % (sub, " ".join(x["name"] + ("/" if x["type"] == "tree" else "") for x in tree(LYRE, sub, ref))))
        except Exception as e:  # noqa: BLE001
            t.append("tree[%s]: нет (%s)" % (sub, e))
    notice("lyrebird %s tree" % ref, t)
    notice("lyrebird %s transports.go" % ref, sigs(LYRE, "transports/transports.go", ref))
    notice("lyrebird %s base.go" % ref, sigs(LYRE, "transports/base/base.go", ref))

t = []
for sub in ("transport", "transport/httpupgrade", "main/client", "common"):
    try:
        t.append("tree[%s]: %s" % (sub, " ".join(x["name"] + ("/" if x["type"] == "tree" else "") for x in tree(WEB, sub, "v0.0.7"))))
    except Exception as e:  # noqa: BLE001
        t.append("tree[%s]: нет (%s)" % (sub, e))
notice("webtunnel v0.0.7 tree", t)
notice("webtunnel client webtunnel.go", sigs(WEB, "main/client/webtunnel.go", "v0.0.7"))
for f in ("transport/httpupgrade/httpupgrade.go", "transport/httpupgrade/client.go"):
    notice("webtunnel " + f, sigs(WEB, f, "v0.0.7"))
