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
                     ["1000003", "Controller", "pw3", "S3"], ["1000004", "Supervisor", "pw4", "SUP"]):
            subprocess.run([admin, "--db", cls.db, "adduser", *args], check=True, capture_output=True)
        cls.port, cls.http_port = free_port(), free_port()
        cls.procs = [
            subprocess.Popen([os.path.join(BUILD, "skynet-fsd"), "--db", cls.db, "--host", "127.0.0.1",
                              "--port", str(cls.port), "--http-port", str(cls.http_port)],
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
        a.send("@N:AFL200:2000:1:55.98:37.40:3000:180:0:0")
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

        b.send("#DPSBI300:1000002")
        self.assertEqual(a.expect("#DP"), "#DPSBI300:1000002")
        for x in (atc, a, b, far):
            x.close()

    def test_ping(self):
        a = self.pilot("AFL500", 1000001, "pw1")
        a.send("$PIAFL500:SERVER:42")
        self.assertEqual(a.expect("$PO"), "$POSERVER:AFL500:42")
        a.close()


if __name__ == "__main__":
    unittest.main()
