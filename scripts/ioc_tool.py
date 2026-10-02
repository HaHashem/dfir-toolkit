#!/usr/bin/env python3
"""Extract, refang and defang indicators from text. No network access.

  cat report.txt | python scripts/ioc_tool.py extract
  python scripts/ioc_tool.py extract report.txt --json
  echo "hxxps://bad[.]example/x" | python scripts/ioc_tool.py refang
  echo "http://bad.example/x 203.0.113.9" | python scripts/ioc_tool.py defang
"""
import argparse, ipaddress, json, re, sys
from collections import Counter, OrderedDict

FAKE_TLDS = {"exe", "dll", "sys", "txt", "log", "png", "jpg", "gif", "js", "css", "html", "htm", "php",
             "aspx", "py", "ps1", "bat", "cmd", "doc", "docx", "xls", "xlsx", "pdf", "zip", "dat", "tmp",
             "ini", "cfg", "json", "xml", "md", "lnk", "vbs", "msi", "scr", "bin", "iso", "rar", "7z", "gz"}

def refang(text):
    t = text
    t = re.sub(r"(?i)\bhxxp(s?)(://|\[:\]//|:\\\\)", lambda m: "http" + m.group(1) + "://", t)
    t = re.sub(r"(?i)\bh\*\*p(s?)://", lambda m: "http" + m.group(1) + "://", t)
    t = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", ".", t, flags=re.I)
    t = re.sub(r"\[\s*@\s*\]|\(\s*@\s*\)|\[at\]", "@", t, flags=re.I)
    t = re.sub(r"\[:\]", ":", t)
    return t

def defang(text):
    t = re.sub(r"(?i)\bhttp(s?)://", lambda m: "hxxp" + m.group(1) + "://", text)
    def dots(m):
        return m.group(0).replace(".", "[.]")
    t = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", dots, t)
    t = re.sub(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
               lambda m: m.group(0).replace(".", "[.]") if m.group(0).split(".")[-1].lower() not in FAKE_TLDS else m.group(0), t, flags=re.I)
    t = t.replace("@", "[@]")
    return t

PATTERNS = OrderedDict([
    ("url", r"\bhttps?://[^\s<>\"'`)\]]+"),
    ("email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b"),
    ("cve", r"\bCVE-\d{4}-\d{4,7}\b"),
    ("ja4", r"\b[tqd][0-9]{2}[di][0-9]{2}[0-9]{2}[a-z0-9]{2}_[a-f0-9]{12}_[a-f0-9]{12}\b"),
    ("sha256", r"\b[a-fA-F0-9]{64}\b"),
    ("sha1", r"\b[a-fA-F0-9]{40}\b"),
    ("hex32", r"\b[a-fA-F0-9]{32}\b"),
    ("ipv4", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    ("domain", r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b"),
])

def extract(text, hex32="md5"):
    """Return {type: Counter}. hex32 decides if 32-hex strings are 'md5' or 'ja3' (they look identical)."""
    t = refang(text)
    found = {}
    consumed = []
    for kind, pat in PATTERNS.items():
        for m in re.finditer(pat, t, flags=re.I if kind in ("domain", "cve") else 0):
            s, e = m.span()
            if kind not in ("url", "email") and any(s >= a and e <= b for a, b in consumed):
                continue
            val = m.group(0).rstrip(".,;:")
            if kind == "domain":
                if val.split(".")[-1].lower() in FAKE_TLDS: continue
                val = val.lower()
            if kind == "cve": val = val.upper()
            if kind in ("sha256", "sha1", "hex32"): val = val.lower()
            if kind == "ipv4":
                try: ipaddress.ip_address(val)
                except ValueError: continue
            key = hex32 if kind == "hex32" else kind
            found.setdefault(key, Counter())[val] += 1
            if kind in ("url", "email"): consumed.append((s, e))
    return found

def is_private(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_link_local

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["extract", "refang", "defang"])
    ap.add_argument("file", nargs="?", help="input file (default: stdin)")
    ap.add_argument("--json", action="store_true", help="JSON output (extract)")
    ap.add_argument("--hex32", choices=["md5", "ja3"], default="md5", help="treat 32-hex strings as md5 or ja3")
    ap.add_argument("--keep-private", action="store_true", help="keep private/internal IPs")
    a = ap.parse_args()
    text = open(a.file, encoding="utf-8", errors="replace").read() if a.file else sys.stdin.read()
    if a.mode == "refang": print(refang(text), end=""); return
    if a.mode == "defang": print(defang(text), end=""); return
    res = extract(text, a.hex32)
    if not a.keep_private and "ipv4" in res:
        res["ipv4"] = Counter({k: v for k, v in res["ipv4"].items() if not is_private(k)})
    if a.json:
        print(json.dumps({k: dict(v) for k, v in res.items() if v}, indent=2)); return
    for kind, c in res.items():
        if not c: continue
        print(f"# {kind} ({len(c)})")
        for val, n in c.most_common(): print(f"{val}\t{n}")
        print()

if __name__ == "__main__":
    main()
