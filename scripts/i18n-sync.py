#!/usr/bin/env python3
"""Sync crates/server/i18n/*.json with the nav.t()/i18n::tr() strings in templates.
Keeps existing lines and order; new keys get the English text and go before the first
greater key; unused keys are dropped. Usage: scripts/i18n-sync.py . [--check]"""
import json, os, sys
repo = sys.argv[1]
tdir = os.path.join(repo, "crates/server/templates")
used = set()
for f in os.listdir(tdir):
    text = open(os.path.join(tdir, f), encoding="utf-8").read()
    for opener in ['nav.t("', 'i18n::tr("']:
        for part in text.split(opener)[1:]:
            used.add(part.split('")')[0])
idir = os.path.join(repo, "crates/server/i18n")
for f in sorted(os.listdir(idir)):
    p = os.path.join(idir, f)
    raw = open(p, encoding="utf-8").read()
    d = json.loads(raw)
    lines = raw.rstrip("\n").split("\n")
    assert lines[0] == "{" and lines[-1] == "}"
    entries = []  # (key, line)
    for ln in lines[1:-1]:
        body = ln.rstrip(",")
        k = list(json.loads("{" + body + "}").keys())[0]
        entries.append((k, body))
    entries = [e for e in entries if e[0] in used]
    have = {k for k, _ in entries}
    for k in sorted(used - have):
        line = "  " + json.dumps(k, ensure_ascii=False) + ": " + json.dumps(k, ensure_ascii=False)
        pos = next((i for i, (ek, _) in enumerate(entries) if ek > k), len(entries))
        entries.insert(pos, (k, line))
    s = "{\n" + ",\n".join(l for _, l in entries) + "\n}" + ("\n" if raw.endswith("\n") else "")
    assert set(json.loads(s)) == used
    if "--check" in sys.argv:
        print(f, "same" if s == raw else "DIFF", len(used - set(d)), "added", len(set(d) - used), "dropped")
    else:
        open(p, "w", encoding="utf-8").write(s)
