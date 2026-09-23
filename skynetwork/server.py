"""SkyNetwork server: TCP network for pilot and ATC clients plus an HTTP data feed."""
import asyncio
import json
import logging
import math
import time

from . import protocol
from .accounts import RATINGS, Accounts

log = logging.getLogger("skynetwork")

PILOT_VIS_NM = 50  # how far pilots see each other
MAX_ATC_RANGE_NM = 600
MIN_ATC_RATING = "S1"


def distance_nm(a, b) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 3440.065 * math.asin(math.sqrt(h))


def _num(v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
        raise protocol.ProtocolError("bad numeric field")
    return v


class Client:
    def __init__(self, writer, account, callsign, role, client_name):
        self.writer = writer
        self.cid = account["cid"]
        self.name = account["name"]
        self.rating = account["rating"]
        self.callsign = callsign
        self.role = role
        self.client_name = client_name
        self.logon_time = time.time()
        self.position = None
        self.flightplan = None

    @property
    def coords(self):
        return (self.position["lat"], self.position["lon"]) if self.position else None

    @property
    def range(self):
        if self.role == "atc" and self.position:
            return self.position["range"]
        return PILOT_VIS_NM

    def send(self, data: bytes):
        if not self.writer.is_closing():
            self.writer.write(data)

    def public(self):
        return {
            "cid": self.cid, "name": self.name, "callsign": self.callsign, "role": self.role,
            "rating": self.rating, "client": self.client_name,
            "logon_time": int(self.logon_time), **(self.position or {}),
            "flightplan": self.flightplan,
        }


class SkyNetworkServer:
    def __init__(self, accounts: Accounts, server_name="SKYNET-1", motd="Welcome to SkyNetwork!"):
        self.accounts = accounts
        self.server_name = server_name
        self.motd = motd
        self.clients: dict[str, Client] = {}

    # ---- visibility -----------------------------------------------------
    def can_see(self, a: Client, b: Client) -> bool:
        if not a.coords or not b.coords:
            return False
        return distance_nm(a.coords, b.coords) <= max(a.range, b.range)

    def broadcast_near(self, src: Client, data: bytes):
        for c in self.clients.values():
            if c is not src and self.can_see(c, src):
                c.send(data)

    # ---- connection handling ---------------------------------------------
    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        client = None
        try:
            client = await self._login(reader, writer)
            if not client:
                return
            log.info("%s (%s) connected from %s as %s", client.callsign, client.cid, peer, client.role)
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    msg = protocol.decode(line)
                    if msg["type"] == "logout":
                        break
                    self._dispatch(client, msg)
                except protocol.ProtocolError as exc:
                    client.send(protocol.encode("error", reason=str(exc)))
                await writer.drain()
        except (ConnectionError, asyncio.LimitOverrunError, ValueError):
            pass
        finally:
            if client and self.clients.get(client.callsign) is client:
                del self.clients[client.callsign]
                bye = protocol.encode("client_left", callsign=client.callsign)
                for c in self.clients.values():
                    c.send(bye)
                log.info("%s disconnected", client.callsign)
            writer.close()

    async def _login(self, reader, writer):
        def fail(reason):
            writer.write(protocol.encode("error", reason=reason))
            return None

        try:
            line = await asyncio.wait_for(reader.readline(), timeout=30)
            msg = protocol.decode(line)
        except (asyncio.TimeoutError, protocol.ProtocolError):
            return fail("login expected")
        if msg["type"] != "login":
            return fail("login expected")
        account = self.accounts.authenticate(msg.get("cid"), msg.get("password"))
        if not account:
            return fail("invalid credentials")
        callsign = str(msg.get("callsign", "")).upper()
        role = msg.get("role")
        if not protocol.valid_callsign(callsign):
            return fail("invalid callsign")
        if role not in protocol.ROLES:
            return fail("invalid role")
        if role == "atc" and RATINGS.index(account["rating"]) < RATINGS.index(MIN_ATC_RATING):
            return fail("rating too low for ATC")
        if callsign in self.clients:
            return fail("callsign in use")
        client = Client(writer, account, callsign, role, str(msg.get("client", "unknown"))[:64])
        self.clients[callsign] = client
        client.send(protocol.encode(
            "welcome", server=self.server_name, protocol=protocol.PROTOCOL_VERSION,
            motd=self.motd, name=account["name"], rating=account["rating"],
        ))
        await writer.drain()
        return client

    # ---- messages -----------------------------------------------------------
    def _dispatch(self, client: Client, msg: dict):
        handler = getattr(self, "on_" + msg["type"], None)
        if handler is None:
            raise protocol.ProtocolError("unknown message type")
        handler(client, msg)

    def on_ping(self, client, msg):
        client.send(protocol.encode("pong", ts=msg.get("ts")))

    def on_position(self, client, msg):
        pos = {"lat": _num(msg.get("lat"), -90, 90), "lon": _num(msg.get("lon"), -180, 180)}
        if client.role == "pilot":
            pos.update(
                alt=_num(msg.get("alt", 0), -2000, 100000),
                gs=_num(msg.get("gs", 0), 0, 5000),
                hdg=_num(msg.get("hdg", 0), 0, 360),
                squawk=str(msg.get("squawk", "2000"))[:4],
                transponder=str(msg.get("transponder", "standby"))[:10],
            )
        else:
            pos.update(
                frequency=str(msg.get("frequency", "199.998"))[:7],
                facility=str(msg.get("facility", "OBS"))[:4],
                range=_num(msg.get("range", 40), 0, MAX_ATC_RANGE_NM),
            )
        client.position = pos
        self.broadcast_near(client, protocol.encode("position", callsign=client.callsign, role=client.role, **pos))

    def on_flightplan(self, client, msg):
        if client.role != "pilot":
            raise protocol.ProtocolError("only pilots file flight plans")
        fields = ("dep", "arr", "alt", "route", "aircraft", "rules", "remarks")
        client.flightplan = {f: str(msg.get(f, ""))[:512] for f in fields}
        data = protocol.encode("flightplan", callsign=client.callsign, **client.flightplan)
        for c in self.clients.values():
            if c.role == "atc":
                c.send(data)

    def on_message(self, client, msg):
        to, text = msg.get("to"), msg.get("text")
        if not isinstance(to, str) or not isinstance(text, str) or not text.strip():
            raise protocol.ProtocolError("bad message")
        data = protocol.encode("message", sender=client.callsign, to=to, text=text[:1024])
        if to == "*":
            if RATINGS.index(client.rating) < RATINGS.index("SUP"):
                raise protocol.ProtocolError("broadcast requires supervisor")
            targets = [c for c in self.clients.values() if c is not client]
        elif to.startswith("@"):  # frequency message: everyone in range
            targets = [c for c in self.clients.values() if c is not client and self.can_see(c, client)]
        else:
            target = self.clients.get(to.upper())
            if not target:
                raise protocol.ProtocolError("no such callsign")
            targets = [target]
        for c in targets:
            c.send(data)

    # ---- data feed ----------------------------------------------------------
    def snapshot(self):
        clients = [c.public() for c in self.clients.values()]
        return {
            "general": {"server": self.server_name, "update": int(time.time()),
                        "connected_clients": len(clients)},
            "pilots": [c for c in clients if c["role"] == "pilot"],
            "controllers": [c for c in clients if c["role"] == "atc"],
        }

    async def handle_http(self, reader, writer):
        try:
            request = await asyncio.wait_for(reader.readline(), timeout=10)
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            parts = request.split()
            if len(parts) >= 2 and parts[1] in (b"/", b"/data.json"):
                body, status = json.dumps(self.snapshot()).encode(), "200 OK"
            else:
                body, status = b'{"error":"not found"}', "404 Not Found"
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
                f"Access-Control-Allow-Origin: *\r\nContent-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n".encode() + body
            )
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()

    async def start(self, host="0.0.0.0", port=6809, http_port=8080):
        fsd = await asyncio.start_server(self.handle, host, port, limit=protocol.MAX_LINE)
        http = await asyncio.start_server(self.handle_http, host, http_port)
        return fsd, http
