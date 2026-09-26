"""Integration tests: start the real skynet-fsd binary and talk to them.

Run after building:  cmake -B build && make -C build && python3 -m unittest discover -s tests
"""
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.request

BUILD = os.environ.get("SKYNET_BUILD", os.path.join(os.path.dirname(__file__), "..", "build"))


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Network(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = os.path.join(cls.tmp.name, "test.db")
        admin = os.path.join(BUILD, "skynet-admin")
        for args in (["1000001", "Pilot One", "pw1"], ["1000002", "Pilot Two", "pw2"],
                     ["1000003", "Controller", "pw3", "S3"], ["1000004", "Supervisor", "pw4", "SUP"],
                     ["1000005", "Rule Breaker", "pw5"], ["1000006", "Demoted Controller", "pw6", "C1"]):
            subprocess.run([admin, "--db", cls.db, "adduser", *args], check=True, capture_output=True)
        cls.port, cls.http_port = free_port(), free_port()
        cls.procs = [
            subprocess.Popen([os.path.join(BUILD, "skynet-fsd"), "--db", cls.db, "--host", "127.0.0.1",
                              "--port", str(cls.port), "--http-port", str(cls.http_port),
                              "--account-check", "1"],
                             stderr=subprocess.DEVNULL),
        ]
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.terminate()
            p.wait()
        cls.tmp.cleanup()


class FsdClient:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), 2)
        self.sock.settimeout(2)
        self.buf = b""

    def send(self, line):
        self.sock.sendall(line.encode() + b"\r\n")

    def recv(self):
        while b"\r\n" not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                raise ConnectionError("closed")
            self.buf += data
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line.decode()

    def expect(self, prefix):
        while True:
            line = self.recv()
            if line.startswith(prefix):
                return line

    def close(self):
        self.sock.close()


class FsdTest(Network):
    def pilot(self, cs, cid, pw):
        c = FsdClient(self.port)
        c.send(f"#AP{cs}:SERVER:{cid}:{pw}:1:100:1:Test Pilot")
        self.assertTrue(c.recv().startswith(f"#TMSERVER:{cs}:"))
        return c

    def atc(self, cs, cid, pw, rating=4):
        c = FsdClient(self.port)
        c.send(f"#AA{cs}:SERVER:Test Controller:{cid}:{pw}:{rating}:100")
        return c

    def admin(self, *args):
        subprocess.run([os.path.join(BUILD, "skynet-admin"), "--db", self.db, *args], check=True, capture_output=True)

    def test_suspension_disconnects_and_blocks_login(self):
        c = self.pilot("SUS1", 1000005, "pw5")
        self.admin("suspend", "1000005")
        self.assertEqual(c.expect("$ER"), "$ERserver:SUS1:013:SUS1:CID suspended")
        with self.assertRaises(ConnectionError):
            c.expect("never")
        c.close()
        again = FsdClient(self.port)
        again.send("#APSUS2:SERVER:1000005:pw5:1:100:1:Test Pilot")
        self.assertIn(":013:SUS2:CID suspended", again.recv())
        again.close()
        # A wrong password still says only "invalid", never "suspended".
        wrong = FsdClient(self.port)
        wrong.send("#APSUS3:SERVER:1000005:nope:1:100:1:Test Pilot")
        self.assertIn(":006:", wrong.recv())
        wrong.close()
        self.admin("unsuspend", "1000005")
        self.pilot("SUS4", 1000005, "pw5").close()

    def test_lowered_rating_disconnects_controller(self):
        c = self.atc("DEMO_APP", 1000006, "pw6", 5)
        self.admin("rating", "1000006", "S2")
        self.assertIn(":011:", c.expect("$ER"))
        c.close()
        self.admin("rating", "1000006", "C1")

    def test_staff_rank_is_apart_from_controller_rating(self):
        # A supervisor who is a C1 controller: connects up to SUP, may broadcast.
        self.admin("adduser", "1000007", "Staff Member", "pw7", "C1")
        self.admin("staff", "1000007", "SUP")
        sup = self.atc("SKY_SUP", 1000007, "pw7", 11)
        self.assertTrue(sup.recv().startswith("#TMSERVER:SKY_SUP:"))
        sup.close()
        # Rank taken away: the controller rating stays, supervisor level is refused.
        self.admin("staff", "1000007", "NONE")
        again = self.atc("SKY_SUP", 1000007, "pw7", 11)
        self.assertIn(":011:", again.recv())
        again.close()
        c1 = self.atc("UUWV_CTR", 1000007, "pw7", 5)
        self.assertTrue(c1.recv().startswith("#TMSERVER:UUWV_CTR:"))
        c1.close()

    def test_old_database_is_migrated(self):
        import sqlite3
        path = os.path.join(self.tmp.name, "old.db")
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE members (cid INTEGER PRIMARY KEY, name TEXT NOT NULL, rating INTEGER NOT NULL DEFAULT 1,"
                       " salt BLOB NOT NULL, hash BLOB NOT NULL, suspended INTEGER NOT NULL DEFAULT 0)")
            db.execute("INSERT INTO members VALUES (1, 'Admin', 12, x'00', x'00', 0), (2, 'Controller', 5, x'00', x'00', 0)")
        subprocess.run([os.path.join(BUILD, "skynet-admin"), "--db", path, "passwd", "1", "x"], check=True, capture_output=True)
        with sqlite3.connect(path) as db:
            rows = db.execute("SELECT cid, rating, staff_rank FROM members ORDER BY cid").fetchall()
        self.assertEqual(rows, [(1, 1, 12), (2, 5, 0)])

    def test_bad_password(self):
        c = FsdClient(self.port)
        c.send("#APAFL1:SERVER:1000001:nope:1:100:1:X")
        self.assertIn(":006:", c.recv())
        c.close()

    def test_login_required(self):
        c = FsdClient(self.port)
        c.send("@N:AFL1:2000:1:55:37:0:0:0:0")
        self.assertIn(":004:", c.recv())
        c.close()

    def test_callsign_in_use_and_rating(self):
        a = self.pilot("AFL100", 1000001, "pw1")
        b = FsdClient(self.port)
        b.send("#APafl100:SERVER:1000002:pw2:1:100:1:X")
        self.assertIn(":001:", b.recv())
        c = self.atc("UUEE_TWR", 1000002, "pw2", rating=2)
        self.assertIn(":011:", c.recv())
        for x in (a, b, c):
            x.close()

    def test_traffic_flightplan_and_text(self):
        atc = self.atc("UUEE_TWR", 1000003, "pw3")
        self.assertTrue(atc.recv().startswith("#TMSERVER:UUEE_TWR:"))
        atc.send("%UUEE_TWR:18100:4:50:4:55.97:37.41:0")
        a = self.pilot("AFL200", 1000001, "pw1")
        b = self.pilot("SBI300", 1000002, "pw2")
        a.send("@N:AFL200:2000:1:55.98:37.40:3000:180:3074:0")  # PBH: heading 270, on the ground
        self.assertTrue(atc.expect("@").startswith("@N:AFL200:"))
        b.send("@N:SBI300:2000:1:55.99:37.42:5000:200:0:0")
        self.assertTrue(a.expect("@").startswith("@N:SBI300:"))
        # Far-away pilot must not be seen.
        far = self.pilot("UTA400", 1000004, "pw4")
        far.send("@N:UTA400:2000:1:43.44:39.95:3000:180:0:0")
        a.send("#TMAFL200:SBI300:ping")
        self.assertEqual(b.expect("#TM"), "#TMAFL200:SBI300:ping")

        a.send("$FPAFL200:*A:I:A320:450:UUEE:1200:0:FL350:ULLI:1:10:3:0:ULLO:/V/:DCT")
        self.assertTrue(atc.expect("$FP").startswith("$FPAFL200:*A:I:A320"))
        atc.send("$CQUUEE_TWR:SERVER:FP:AFL200")
        self.assertIn("ULLI", atc.expect("$FP"))
        atc.send("#TMUUEE_TWR:@18100:AFL200 cleared to land")
        self.assertEqual(a.expect("#TM"), "#TMUUEE_TWR:@18100:AFL200 cleared to land")
        # Spoofed source is rejected.
        a.send("#TMSBI300:UUEE_TWR:spoof")
        self.assertIn(":005:", a.expect("$ER"))
        # Broadcast needs a supervisor.
        a.send("#TMAFL200:*:hello all")
        self.assertIn(":011:", a.expect("$ER"))

        feed = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.http_port}/data.json", timeout=2))
        callsigns = {p["callsign"] for p in feed["pilots"]}
        self.assertTrue({"AFL200", "SBI300", "UTA400"} <= callsigns)
        self.assertEqual(feed["controllers"][0]["frequency"], "118.100")
        afl = next(p for p in feed["pilots"] if p["callsign"] == "AFL200")
        self.assertEqual((afl["heading"], afl["on_ground"]), (270, True))

        b.send("#DPSBI300:1000002")
        self.assertEqual(a.expect("#DP"), "#DPSBI300:1000002")
        for x in (atc, a, b, far):
            x.close()

    def test_controller_coordination(self):
        twr = self.atc("UUEE_TWR", 1000003, "pw3")
        ctr = self.atc("UUWV_CTR", 1000004, "pw4")
        pilot = self.pilot("AFL600", 1000001, "pw1")
        # Shared data goes to every other controller, never to pilots.
        twr.send("$CQUUEE_TWR:@94835:IT:AFL600")
        self.assertEqual(ctr.expect("$CQ"), "$CQUUEE_TWR:@94835:IT:AFL600")
        pilot.send("$CQAFL600:@94835:IT:AFL600")
        self.assertIn(":011:", pilot.expect("$ER"))
        # Handoff and its acceptance are point-to-point.
        twr.send("$HOUUEE_TWR:UUWV_CTR:AFL600")
        self.assertEqual(ctr.expect("$HO"), "$HOUUEE_TWR:UUWV_CTR:AFL600")
        ctr.send("$HAUUWV_CTR:UUEE_TWR:AFL600")
        self.assertEqual(twr.expect("$HA"), "$HAUUWV_CTR:UUEE_TWR:AFL600")
        for x in (twr, ctr, pilot):
            x.close()

    def test_wallop_reaches_supervisors_and_answers_the_sender(self):
        def server_reply(client):
            # The next server text that answers the call (the welcome lines are skipped).
            while True:
                line = client.expect("#TMSERVER")
                if "upervisor" in line:
                    return line

        pilot = self.pilot("AFL700", 1000001, "pw1")
        # Nobody to call: the server says so (a supervisor from an earlier test may take a moment to go).
        for _ in range(20):
            pilot.send("#TMAFL700:*S:need help")
            reply = server_reply(pilot)
            if "No supervisors" in reply:
                break
            time.sleep(0.1)
        self.assertIn("No supervisors", reply)

        sup = self.atc("UUWV_SUP", 1000004, "pw4", rating=11)
        self.assertTrue(sup.recv().startswith("#TMSERVER:UUWV_SUP:"))
        other = self.pilot("SBI701", 1000002, "pw2")
        pilot.send("#TMAFL700:*S:need help")
        self.assertEqual(sup.expect("#TMAFL700"), "#TMAFL700:*S:need help")
        self.assertIn("recipients: 1", server_reply(pilot))
        # Only supervisors get it: the pilot's next text is the marker, not the call.
        pilot.send("#TMAFL700:SBI701:marker")
        self.assertEqual(other.expect("#TMAFL700"), "#TMAFL700:SBI701:marker")
        for x in (pilot, sup, other):
            x.close()

    def test_supervisor_commands(self):
        import sqlite3
        self.admin("adduser", "1000010", "Second Sup", "pw10", "C1")
        self.admin("staff", "1000010", "SUP")
        self.admin("adduser", "1000011", "Network Sup", "pw11", "C1")
        self.admin("staff", "1000011", "SUP")
        self.admin("adduser", "1000012", "Network Admin", "pw12", "C1")
        self.admin("staff", "1000012", "ADM")

        def reply(client, word):
            while True:
                line = client.expect("#TMSERVER")
                if word in line:
                    return line

        # Supervisor positions need the rank.
        fake = self.atc("UUEE_SUP", 1000003, "pw3", 4)
        self.assertIn(":011:", fake.recv())
        fake.close()
        fake = self.atc("SKY_ADM", 1000011, "pw11", 11)
        self.assertIn(":011:", fake.recv())
        fake.close()

        sup2 = self.atc("SKY3_SUP", 1000010, "pw10", 11)
        sup = self.atc("SKY1_SUP", 1000011, "pw11", 11)
        adm = self.atc("SKY_ADM", 1000012, "pw12", 12)
        pilot = self.pilot("AFL800", 1000001, "pw1")
        pilot.send("@N:AFL800:2000:1:55.98:37.40:3500:180:0:0")
        time.sleep(0.2)

        # Members without a staff rank get nothing.
        pilot.send("$CQAFL800:SERVER:WHOIS:SKY1_SUP")
        self.assertIn(":011:", pilot.expect("$ER"))

        # WHOIS by callsign and by CID; only an administrator sees the IP.
        sup.send("$CQSKY1_SUP:SERVER:WHOIS:AFL800")
        line = reply(sup, "AFL800:")
        self.assertIn("CID 1000001", line)
        self.assertNotIn("IP ", line)
        adm.send("$CQSKY_ADM:SERVER:WHOIS:1000001")
        self.assertIn("IP 127.0.0.1", reply(adm, "AFL800:"))

        # FIND answers with the position, anywhere on the network.
        sup.send("$CQSKY1_SUP:SERVER:FIND:afl800")
        self.assertEqual(sup.expect("$CRSERVER"), "$CRSERVER:SKY1_SUP:FIND:AFL800:55.980000:37.400000:3500")

        sup.send("$CQSKY1_SUP:SERVER:STAFF")
        staff = reply(sup, "Staff online")
        for part in ("SKY3_SUP (SUP)", "SKY1_SUP (SUP)", "SKY_ADM (ADM)"):
            self.assertIn(part, staff)
        sup.send("$CQSKY1_SUP:SERVER:ONLINE")
        self.assertIn("pilots", reply(sup, "Online:"))

        # A supervisor does not act on other supervisors or administrators; a reason is required.
        sup.send("$CQSKY1_SUP:SERVER:KILL:SKY3_SUP:test")
        self.assertIn("cannot disconnect SKY3_SUP", reply(sup, "cannot"))
        sup.send("$CQSKY1_SUP:SERVER:KILL:SKY_ADM:test")
        self.assertIn("cannot disconnect", reply(sup, "cannot"))
        sup.send("$CQSKY1_SUP:SERVER:KILL:AFL800")
        self.assertIn("Usage", reply(sup, "Usage"))

        sup.send("$CQSKY1_SUP:SERVER:WARN:AFL800:follow ATC instructions")
        self.assertIn("Warning from supervisor SKY1_SUP: follow ATC instructions", reply(pilot, "Warning"))

        sup.send("$CQSKY1_SUP:SERVER:KILL:AFL800:ignoring ATC: repeatedly")
        self.assertIn("Reason: ignoring ATC: repeatedly", reply(pilot, "disconnected"))
        self.assertEqual(pilot.expect("$!!"), "$!!SERVER:AFL800:ignoring ATC: repeatedly")
        with self.assertRaises(ConnectionError):
            pilot.expect("never")
        self.assertIn("AFL800 (CID 1000001) disconnected", reply(sup, "disconnected"))
        self.assertTrue(adm.expect("#DP").startswith("#DPAFL800"))
        with sqlite3.connect(self.db) as db:
            row = db.execute("SELECT actor_cid, action, target FROM audit_log WHERE action = 'network-kill'").fetchone()
        self.assertEqual(row, (1000011, "network-kill", "AFL800 (CID 1000001)"))

        # An administrator may disconnect a supervisor; a supervisor whose rank is taken away is disconnected.
        adm.send("$CQSKY_ADM:SERVER:KILL:SKY3_SUP:test")
        self.assertIn("SKY3_SUP (CID 1000010) disconnected", reply(adm, "disconnected"))
        self.admin("staff", "1000011", "NONE")
        self.assertIn(":011:", sup.expect("$ER"))  # connected as SUP without the rank any more: disconnected
        for x in (sup2, sup, adm, pilot):
            x.close()

    def test_ping(self):
        a = self.pilot("AFL500", 1000001, "pw1")
        a.send("$PIAFL500:SERVER:42")
        self.assertEqual(a.expect("$PO"), "$POSERVER:AFL500:42")
        a.close()


if __name__ == "__main__":
    unittest.main()
