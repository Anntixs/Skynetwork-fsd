"""Minimal async client library, the base for future pilot/ATC programs."""
import asyncio

from . import protocol


class SkyNetworkClient:
    def __init__(self):
        self.reader = self.writer = None

    async def connect(self, host, port, cid, password, callsign, role="pilot", client="skynetwork-py/0.1"):
        self.reader, self.writer = await asyncio.open_connection(host, port, limit=protocol.MAX_LINE)
        await self.send("login", cid=cid, password=password, callsign=callsign, role=role, client=client)
        reply = await self.recv()
        if reply["type"] != "welcome":
            raise ConnectionError(reply.get("reason", "login failed"))
        return reply

    async def send(self, msg_type, **fields):
        self.writer.write(protocol.encode(msg_type, **fields))
        await self.writer.drain()

    async def recv(self):
        line = await self.reader.readline()
        if not line:
            raise ConnectionError("disconnected")
        return protocol.decode(line)

    async def close(self):
        if self.writer:
            try:
                await self.send("logout")
            except ConnectionError:
                pass
            self.writer.close()
