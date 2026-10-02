# dfir-toolkit

Small command-line tools for SOC and DFIR work. They are written to be read: each is one file, uses the Python standard library where possible, works offline, and has tests.

> **Handle evidence carefully.** Work on copies. None of these tools contact the internet. The lookup links that `hash_triage.py` prints are only links: opening one tells that website the hash, so do not search confidential files on third-party sites. Nothing here contains employer data.

| Tool | What it does | Needs |
|---|---|---|
| [`scripts/ioc_tool.py`](scripts/ioc_tool.py) | Extracts IPs, domains, URLs, emails, CVEs, hashes and JA4 from text. Refangs and defangs. Hides private IPs by default | Python 3.9+ |
| [`scripts/hash_triage.py`](scripts/hash_triage.py) | Hashes files or folders (MD5, SHA1, SHA256), prints lookup links, writes CSV | Python 3.9+ |
| [`scripts/ja4_stack.py`](scripts/ja4_stack.py) | Stacks JA3 and JA4 TLS fingerprints from a capture: sources, destinations, SNI. Finds rare fingerprints | `tshark` (or a tshark field export) |
| [`scripts/evtx_triage.py`](scripts/evtx_triage.py) | Pulls event IDs of interest from `.evtx` files using presets (logons, accounts, persistence, ransomware, PowerShell, Kerberos). Table or CSV | `python-evtx` |

## Quick start
```
git clone https://github.com/HaHashem/dfir-toolkit
cd dfir-toolkit

# indicators from a report or alert text
python scripts/ioc_tool.py extract report.txt
echo "hxxps://bad[.]example/x" | python scripts/ioc_tool.py refang
echo "http://bad.example/x 203.0.113.9" | python scripts/ioc_tool.py defang

# hash a folder of samples
python scripts/hash_triage.py ./evidence --csv hashes.csv

# which TLS clients are in this capture, and which are rare
python scripts/ja4_stack.py capture.pcapng --rare 2

# failed and successful logons from a Security log
pip install python-evtx
python scripts/evtx_triage.py Security.evtx --preset logons --since 2026-10-01
```

## JA3 versus MD5
A JA3 value and an MD5 hash are both 32 hex characters, so no tool can tell them apart from the text. `ioc_tool.py` treats them as MD5 unless you pass `--hex32 ja3`. JA4 has a distinct format and is detected automatically. See [JA3 and JA4 explained](https://hahashem.github.io/article.html?slug=network-tls-fingerprint-hunting-ja3-ja4).

## Tests
```
python -m unittest discover -s tests -v
```
The tests cover refang and defang, extraction by indicator type, file hashing against known values, fingerprint stacking, and event parsing from sample event XML. The `evtx_triage.py` tests use synthetic event XML. Run it against one of your own logs before relying on it.

## Limits
- Fingerprints identify client software, not intent. Compare with a baseline before acting.
- `ja4_stack.py` needs a tshark build that knows the JA3/JA4 fields. Check with `tshark -G fields | grep -i ja`.
- Extraction is regex based and will miss some obfuscation and flag some false positives. Review the output.

## Related
- [ioc-checker](https://github.com/HaHashem/ioc-checker): the in-browser indicator tool
- [soc-hunting-queries](https://github.com/HaHashem/soc-hunting-queries) and [sigma-rules](https://github.com/HaHashem/sigma-rules)
- [Portfolio and articles](https://hahashem.github.io)

## License
[MIT](LICENSE)
