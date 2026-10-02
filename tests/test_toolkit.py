import os, sys, tempfile, unittest, csv
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import ioc_tool, hash_triage, ja4_stack, evtx_triage

class IocTests(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(ioc_tool.refang("hxxps://bad[.]example[.]com/x"), "https://bad.example.com/x")
        self.assertEqual(ioc_tool.refang("user[@]example(.)org"), "user@example.org")
    def test_defang(self):
        d = ioc_tool.defang("http://bad.example.com/x 203.0.113.9")
        self.assertIn("hxxp://bad[.]example[.]com/x", d)
        self.assertIn("203[.]0[.]113[.]9", d)
    def test_extract_types(self):
        t = ("hxxps://evil[.]example/path 203.0.113.7 CVE-2024-3094 "
             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
             "t13d1516h2_8daaf6152771_02713d6af862 a@b.example 192.168.1.5 notes.txt")
        r = ioc_tool.extract(t)
        self.assertIn("https://evil.example/path", r["url"])
        self.assertIn("203.0.113.7", r["ipv4"])
        self.assertIn("CVE-2024-3094", r["cve"])
        self.assertEqual(len(r["sha256"]), 1)
        self.assertIn("t13d1516h2_8daaf6152771_02713d6af862", r["ja4"])
        self.assertIn("a@b.example", r["email"])
        self.assertNotIn("notes.txt", r.get("domain", {}))
    def test_hex32_selector(self):
        h = "e7d705a3286e19ea42f587b344ee6865"
        self.assertIn(h, ioc_tool.extract(h, "md5")["md5"])
        self.assertIn(h, ioc_tool.extract(h, "ja3")["ja3"])
    def test_private_ip(self):
        self.assertTrue(ioc_tool.is_private("10.1.2.3"))
        self.assertFalse(ioc_tool.is_private("8.8.8.8"))

class HashTests(unittest.TestCase):
    def test_known_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "a.bin")
            with open(p, "wb") as fh: fh.write(b"abc")
            r = hash_triage.hash_file(p)
            self.assertEqual(r["md5"], "900150983cd24fb0d6963f7d28e17f72")
            self.assertEqual(r["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
            self.assertEqual(r["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            self.assertEqual(r["size"], 3)
    def test_rows_and_links(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "x"), "wb") as fh: fh.write(b"abc")
            rows = hash_triage.rows([d, os.path.join(d, "missing")])
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["virustotal"].endswith(rows[0]["sha256"]))

class Ja4Tests(unittest.TestCase):
    def test_parse_and_stack(self):
        tsv = ("10.0.0.5\t203.0.113.1\ta.example\t" + "a"*32 + "\tt13d1516h2_8daaf6152771_02713d6af862\n"
               "10.0.0.6\t203.0.113.2\tb.example\t" + "a"*32 + "\tt13d1516h2_8daaf6152771_02713d6af862\n"
               "10.0.0.7\t198.51.100.9\t\t\tt13i0709_aaaaaaaaaaaa_bbbbbbbbbbbb\n\n")
        rows = ja4_stack.parse(tsv)
        self.assertEqual(len(rows), 3)
        s = ja4_stack.stack(rows, 4)
        self.assertEqual(s[0]["sources"], 2)
        self.assertEqual(s[1]["fingerprint"], "t13i0709_aaaaaaaaaaaa_bbbbbbbbbbbb")
        s3 = ja4_stack.stack(rows, 3)
        self.assertEqual(len(s3), 1)

EVT = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>
<TimeCreated SystemTime="2026-10-02T03:10:11.123Z"/><Computer>WS-031</Computer></System>
<EventData><Data Name="TargetUserName">asmith</Data><Data Name="IpAddress">203.0.113.50</Data><Data Name="LogonType">3</Data></EventData></Event>"""

class EvtxTests(unittest.TestCase):
    def test_parse_event(self):
        r = evtx_triage.parse_event(EVT)
        self.assertEqual(r["event_id"], 4625)
        self.assertEqual(r["computer"], "WS-031")
        self.assertEqual(r["data"]["IpAddress"], "203.0.113.50")
        self.assertIn("TargetUserName=asmith", evtx_triage.summarize(r))
    def test_bad_xml(self):
        self.assertIsNone(evtx_triage.parse_event("<nope"))
    def test_select(self):
        r = evtx_triage.parse_event(EVT)
        self.assertEqual(len(list(evtx_triage.select([r, None], {4625}))), 1)
        self.assertEqual(len(list(evtx_triage.select([r], {4624}))), 0)
        self.assertEqual(len(list(evtx_triage.select([r], {4625}, since="2026-10-03"))), 0)
    def test_presets_have_ids(self):
        for k, v in evtx_triage.PRESETS.items():
            self.assertTrue(all(isinstance(i, int) for i in v), k)

if __name__ == "__main__":
    unittest.main()
