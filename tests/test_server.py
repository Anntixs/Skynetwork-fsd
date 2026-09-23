import asyncio
import json
import unittest

from skynetwork.accounts import Accounts
from skynetwork.client import SkyNetworkClient
from skynetwork.server import SkyNetworkServer, distance_nm


class ServerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        acc = Accounts(":memory:")
        acc.create(1000001, "Pilot One", "pw1")
        acc.create(1000002, "Pilot Two", "pw2")
        acc.create(1000003, "Controller", "pw3", rating="S3")
        self.server = SkyNetworkServer(acc)
        self.fsd, self.http = await self.server.start("127.0.0.1", 0, 0)
        self.port = self.fsd.sockets[0].getsockname()[1]
        self.http_port = self.http.sockets[0].getsockname()[1]
        self.clients = []

    async def asyncTearDown(self):
        for c in self.clients:
            await c.close()
        self.fsd.close()
        self.http.close()

    async def connect(self, cid, pw, cs, role="pilot"):
        c = SkyNetworkClient()
        self.clients.append(c)
        await c.connect("127.0.0.1", self.port, cid, pw, cs, role)
        return c

    async def recv(self, c):
        return await asyncio.wait_for(c.recv(), 2)

    async def test_bad_password(self):
        with self.assertRaisesRegex(ConnectionError, "invalid credentials"):
            await self.connect(1000001, "wrong", "AFL123")

    async def test_duplicate_callsign_and_atc_rating(self):
        await self.connect(1000001, "pw1", "AFL123")
        with self.assertRaisesRegex(ConnectionError, "in use"):
            await self.connect(1000002, "pw2", "afl123")
        with self.assertRaisesRegex(ConnectionError, "rating"):
            await self.connect(1000002, "pw2", "UUEE_TWR", "atc")

    async def test_positions_and_messages(self):
        a = await self.connect(1000001, "pw1", "AFL123")
        b = await self.connect(1000002, "pw2", "SBI456")
        atc = await self.connect(1000003, "pw3", "UUEE_TWR", "atc")
        await atc.send("position", lat=55.97, lon=37.41, frequency="118.100", facility="TWR", range=50)
        await a.send("position", lat=55.98, lon=37.40, alt=3000, gs=180, hdg=250)
        self.assertEqual((await self.recv(atc))["callsign"], "AFL123")
        await b.send("position", lat=55.99, lon=37.42, alt=5000, gs=200, hdg=70)
        self.assertEqual((await self.recv(a))["callsign"], "SBI456")
        await a.send("flightplan", dep="UUEE", arr="ULLI", aircraft="A320", route="DCT")
        fp = await self.recv(atc)
        while fp["type"] != "flightplan":
            fp = await self.recv(atc)
        self.assertEqual(fp["arr"], "ULLI")
        await atc.send("message", to="afl123", text="Cleared to land")
        msg = await self.recv(a)
        while msg["type"] != "message":
            msg = await self.recv(a)
        self.assertEqual(msg["sender"], "UUEE_TWR")

        r, w = await asyncio.open_connection("127.0.0.1", self.http_port)
        w.write(b"GET /data.json HTTP/1.1\r\nHost: x\r\n\r\n")
        raw = await r.read()
        data = json.loads(raw.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(len(data["pilots"]), 2)
        self.assertEqual(data["controllers"][0]["callsign"], "UUEE_TWR")
        w.close()

    async def test_invalid_field_rejected(self):
        a = await self.connect(1000001, "pw1", "AFL123")
        await a.send("position", lat=500, lon=0)
        self.assertEqual((await self.recv(a))["type"], "error")

    def test_distance(self):
        self.assertAlmostEqual(distance_nm((55.97, 37.41), (59.80, 30.26)), 327, delta=5)


if __name__ == "__main__":
    unittest.main()
