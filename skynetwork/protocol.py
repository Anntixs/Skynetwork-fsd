"""SkyNetwork wire protocol.

Every message is one line of UTF-8 JSON terminated by '\\n':

    {"type": "<message type>", ...fields}

Client -> server:
    login      {"cid", "password", "callsign", "role": "pilot"|"atc", "name",
                "client": "<software name/version>"}
    position   pilot: {"lat", "lon", "alt", "gs", "hdg", "squawk", "transponder"}
               atc:   {"lat", "lon", "frequency", "facility", "range"}
    flightplan {"dep", "arr", "alt", "route", "aircraft", "rules", "remarks"}
    message    {"to": "<callsign>"|"*"|"@<freq>", "text"}
    ping       {"ts"}
    logout     {}

Server -> client:
    welcome, error, position, flightplan, message, pong, client_left
"""
import json

PROTOCOL_VERSION = 1
MAX_LINE = 8192
ROLES = ("pilot", "atc")


class ProtocolError(Exception):
    pass


def encode(msg_type: str, **fields) -> bytes:
    return (json.dumps({"type": msg_type, **fields}, separators=(",", ":")) + "\n").encode()


def decode(line: bytes) -> dict:
    if len(line) > MAX_LINE:
        raise ProtocolError("line too long")
    try:
        msg = json.loads(line)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ProtocolError("invalid json") from exc
    if not isinstance(msg, dict) or not isinstance(msg.get("type"), str):
        raise ProtocolError("missing message type")
    return msg


def valid_callsign(cs) -> bool:
    return isinstance(cs, str) and 2 <= len(cs) <= 12 and all(c.isalnum() or c == "_" for c in cs)
