#!/usr/bin/env python3
"""Hash files and print lookup links. Hashing is local. Nothing is uploaded or contacted.

  python scripts/hash_triage.py suspicious.exe dropper.dll
  python scripts/hash_triage.py ./evidence --csv hashes.csv

Opening a lookup link tells that site the hash, so do not search confidential files on third-party sites.
"""
import argparse, csv, hashlib, os, sys

LINKS = {
    "virustotal": "https://www.virustotal.com/gui/file/{h}",
    "malwarebazaar": "https://bazaar.abuse.ch/browse.php?search=sha256%3A{h}",
    "hybrid_analysis": "https://www.hybrid-analysis.com/search?query={h}",
    "otx": "https://otx.alienvault.com/indicator/file/{h}",
}

def hash_file(path, chunk=1024 * 1024):
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b: break
            size += len(b)
            md5.update(b); sha1.update(b); sha256.update(b)
    return {"path": path, "size": size, "md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

def walk(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for name in sorted(files): yield os.path.join(root, name)
        elif os.path.isfile(p):
            yield p
        else:
            print(f"skipped (not found): {p}", file=sys.stderr)

def rows(paths):
    out = []
    for f in walk(paths):
        try:
            r = hash_file(f)
        except OSError as e:
            print(f"skipped ({e.strerror}): {f}", file=sys.stderr); continue
        for k, u in LINKS.items(): r[k] = u.format(h=r["sha256"])
        out.append(r)
    return out

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--csv", help="write results to a CSV file")
    a = ap.parse_args()
    r = rows(a.paths)
    for x in r:
        print(f"{x['path']}\n  size   {x['size']}\n  md5    {x['md5']}\n  sha1   {x['sha1']}\n  sha256 {x['sha256']}")
        for k in LINKS: print(f"  {k}: {x[k]}")
        print()
    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(r[0].keys()) if r else ["path"])
            w.writeheader(); w.writerows(r)
        print(f"wrote {a.csv}")

if __name__ == "__main__":
    main()
