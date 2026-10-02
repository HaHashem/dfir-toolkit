#!/usr/bin/env python3
"""Stack TLS client fingerprints (JA3 and JA4) from a packet capture.

  python scripts/ja4_stack.py capture.pcapng            # needs tshark
  python scripts/ja4_stack.py --tsv fields.tsv          # or a tshark field export
  python scripts/ja4_stack.py capture.pcapng --rare 2   # fingerprints seen from <= 2 sources

The tshark export is tab separated: ip.src, ip.dst, SNI, ja3, ja4 (any may be empty).
Check that your tshark build has the fields:  tshark -G fields | grep -i ja
Fingerprints identify client software, not intent. Compare against a baseline before acting.
"""
import argparse, shutil, subprocess, sys
from collections import defaultdict

FIELDS = ["ip.src", "ip.dst", "tls.handshake.extensions_server_name", "tls.handshake.ja3", "tls.handshake.ja4"]

def run_tshark(pcap):
    exe = shutil.which("tshark")
    if not exe:
        sys.exit("tshark not found. Install Wireshark/tshark, or use --tsv with an exported file.")
    cmd = [exe, "-r", pcap, "-Y", "tls.handshake.type == 1", "-T", "fields", "-E", "separator=/t"]
    for f in FIELDS: cmd += ["-e", f]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("tshark failed: " + p.stderr.strip()[:300])
    return p.stdout

def parse(tsv_text):
    """Return list of (src, dst, sni, ja3, ja4)."""
    rows = []
    for line in tsv_text.splitlines():
        if not line.strip(): continue
        parts = line.split("\t") + [""] * 5
        rows.append(tuple(p.strip() for p in parts[:5]))
    return rows

def stack(rows, key_index):
    """key_index 3 = ja3, 4 = ja4. Returns list of dicts sorted by source count then connections."""
    g = defaultdict(lambda: {"conns": 0, "src": set(), "dst": set(), "sni": set()})
    for r in rows:
        k = r[key_index]
        if not k: continue
        e = g[k]; e["conns"] += 1
        if r[0]: e["src"].add(r[0])
        if r[1]: e["dst"].add(r[1])
        if r[2]: e["sni"].add(r[2])
    out = [{"fingerprint": k, "connections": v["conns"], "sources": len(v["src"]),
            "destinations": len(v["dst"]), "sni": sorted(v["sni"])[:3], "src_list": sorted(v["src"])} for k, v in g.items()]
    return sorted(out, key=lambda x: (-x["sources"], -x["connections"]))

def print_table(title, items, rare=None):
    print(f"\n== {title} ==")
    if rare is not None: items = [i for i in items if i["sources"] <= rare]
    if not items: print("(none)"); return
    print(f"{'connections':>11} {'sources':>7} {'dests':>5}  fingerprint / sample SNI")
    for i in items[:40]:
        print(f"{i['connections']:>11} {i['sources']:>7} {i['destinations']:>5}  {i['fingerprint']}  {', '.join(i['sni'])}")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", nargs="?")
    ap.add_argument("--tsv", help="tshark field export instead of a pcap")
    ap.add_argument("--rare", type=int, help="only show fingerprints used by this many sources or fewer")
    a = ap.parse_args()
    if not a.pcap and not a.tsv: ap.error("give a pcap or --tsv")
    text = open(a.tsv).read() if a.tsv else run_tshark(a.pcap)
    rows = parse(text)
    print(f"{len(rows)} ClientHello records")
    print_table("JA4", stack(rows, 4), a.rare)
    print_table("JA3", stack(rows, 3), a.rare)

if __name__ == "__main__":
    main()
