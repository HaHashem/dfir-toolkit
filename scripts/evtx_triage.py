#!/usr/bin/env python3
"""Pull the events that matter out of Windows .evtx files and print or export them.

  pip install python-evtx
  python scripts/evtx_triage.py Security.evtx --preset logons
  python scripts/evtx_triage.py System.evtx --ids 7045,7036 --csv services.csv
  python scripts/evtx_triage.py Security.evtx --preset ransomware --since 2026-10-01
  python scripts/evtx_triage.py Security.evtx --all --csv everything.csv

Presets (event IDs): see PRESETS below. Read-only: it never modifies the log.
Work on a copy of the evidence. Field names come from the event's own EventData.
"""
import argparse, csv, os, sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

PRESETS = {
    "logons": {4624: "Logon success", 4625: "Logon failure", 4634: "Logoff", 4647: "User initiated logoff",
               4648: "Explicit credentials logon", 4672: "Special privileges assigned", 4776: "NTLM credential validation"},
    "accounts": {4720: "User created", 4722: "User enabled", 4723: "Password change attempt", 4724: "Password reset",
                 4725: "User disabled", 4726: "User deleted", 4728: "Added to global group", 4732: "Added to local group",
                 4738: "User changed", 4756: "Added to universal group", 4740: "Account locked out"},
    "persistence": {4698: "Scheduled task created", 4699: "Scheduled task deleted", 4702: "Scheduled task updated",
                    4697: "Service installed (Security)", 7045: "Service installed (System)"},
    "ransomware": {1102: "Audit log cleared", 104: "Event log cleared", 4719: "Audit policy changed",
                   7036: "Service state change", 7040: "Service start type changed", 7045: "Service installed (System)"},
    "powershell": {4103: "Module logging", 4104: "Script block logging", 4688: "Process creation", 400: "Engine started", 800: "Pipeline execution"},
    "kerberos": {4768: "TGT requested", 4769: "Service ticket requested", 4771: "Pre-auth failed", 4662: "Directory object access"},
}

def parse_event(xml_text):
    """Parse one event's XML into a flat dict. Returns None if it is not a valid event."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    sysd = root.find("e:System", NS)
    if sysd is None: return None
    eid = sysd.find("e:EventID", NS)
    tc = sysd.find("e:TimeCreated", NS)
    comp = sysd.find("e:Computer", NS)
    prov = sysd.find("e:Provider", NS)
    rec = {
        "event_id": int(eid.text) if eid is not None and (eid.text or "").strip().isdigit() else None,
        "time": tc.get("SystemTime") if tc is not None else "",
        "computer": comp.text if comp is not None else "",
        "provider": prov.get("Name") if prov is not None else "",
    }
    ed = root.find("e:EventData", NS)
    data = {}
    if ed is not None:
        for i, d in enumerate(ed.findall("e:Data", NS)):
            data[d.get("Name") or f"Data{i}"] = (d.text or "").strip()
    rec["data"] = data
    return rec

def summarize(rec):
    d = rec["data"]
    keys = ["TargetUserName", "SubjectUserName", "IpAddress", "WorkstationName", "LogonType", "Status", "SubStatus", "ServiceName",
            "ImagePath", "TaskName", "NewProcessName", "CommandLine", "ParentProcessName", "ScriptBlockText",
            "MemberName", "TargetDomainName"]
    bits = [f"{k}={d[k][:120]}" for k in keys if d.get(k)]
    return "; ".join(bits)

def iter_events(path):
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        sys.exit("python-evtx is not installed. Run:  pip install python-evtx")
    with Evtx(path) as log:
        for record in log.records():
            try:
                yield parse_event(record.xml())
            except Exception:
                continue

MEANINGS = {k: v for preset in PRESETS.values() for k, v in preset.items()}

def select(events, ids, since=None):
    """ids=None means keep every event."""
    for r in events:
        if r is None or (ids is not None and r["event_id"] not in ids): continue
        if since and r["time"] and r["time"][:10] < since: continue
        yield r

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evtx", nargs="+")
    ap.add_argument("--preset", choices=sorted(PRESETS))
    ap.add_argument("--ids", help="comma separated event IDs, for example 4624,4625")
    ap.add_argument("--all", action="store_true", help="keep every event (combine with --since or --limit on big logs)")
    ap.add_argument("--since", help="YYYY-MM-DD, keep events on or after this date")
    ap.add_argument("--csv", help="write results to CSV")
    ap.add_argument("--limit", type=int, default=0, help="stop after N matches (0 = all)")
    a = ap.parse_args()
    ids = {}
    if a.preset: ids.update(PRESETS[a.preset])
    if a.ids:
        for x in a.ids.split(","):
            x = x.strip()
            if x.lower() in ("all", "*"): a.all = True; continue
            try: ids.setdefault(int(x), MEANINGS.get(int(x), ""))
            except ValueError: ap.error(f"--ids needs numbers like 4624,4625 (got '{x}'). For everything use --all")
    if not ids and not a.all: ap.error("give --preset, --ids or --all")
    if a.all: ids = None
    if a.csv and a.csv.lower().endswith((".xlsx", ".xls")):
        ap.error("--csv writes a plain CSV. Name it something.csv (Excel opens it fine)")
    missing = [p for p in a.evtx if not os.path.isfile(p)]
    if missing:
        sys.exit("File not found: " + ", ".join(missing) +
                 "\nExport a log first (run as Administrator):  wevtutil epl Security Security.evtx")
    rows, n = [], 0
    for path in a.evtx:
        for r in select(iter_events(path), ids, a.since):
            rows.append({"file": path, "time": r["time"], "event_id": r["event_id"], "meaning": MEANINGS.get(r["event_id"], ""),
                         "computer": r["computer"], "summary": summarize(r)})
            n += 1
            if a.limit and n >= a.limit: break
    rows.sort(key=lambda x: x["time"])
    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["file", "time", "event_id", "meaning", "computer", "summary"])
            w.writeheader(); w.writerows(rows)
        print(f"wrote {len(rows)} rows to {a.csv}")
    else:
        for r in rows: print(f"{r['time'][:19]}  {r['event_id']:<5} {r['meaning']:<28} {r['computer']}  {r['summary']}")
        print(f"\n{len(rows)} events", file=sys.stderr)

if __name__ == "__main__":
    main()
