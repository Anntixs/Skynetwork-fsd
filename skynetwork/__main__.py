"""Command line: run the server or manage members.

    python -m skynetwork serve [--port 6809] [--http-port 8080] [--db skynetwork.db]
    python -m skynetwork adduser CID "Name" PASSWORD [--rating S1]
    python -m skynetwork rating CID RATING
    python -m skynetwork suspend CID | unsuspend CID
"""
import argparse
import asyncio
import logging

from .accounts import RATINGS, Accounts
from .server import SkyNetworkServer


async def _serve(args):
    server = SkyNetworkServer(Accounts(args.db), args.name, args.motd)
    fsd, http = await server.start(args.host, args.port, args.http_port)
    logging.info("SkyNetwork %s listening on %s:%d (data feed on :%d)", args.name, args.host, args.port, args.http_port)
    async with fsd, http:
        await asyncio.gather(fsd.serve_forever(), http.serve_forever())


def main():
    p = argparse.ArgumentParser(prog="skynetwork")
    p.add_argument("--db", default="skynetwork.db")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=6809)
    s.add_argument("--http-port", type=int, default=8080)
    s.add_argument("--name", default="SKYNET-1")
    s.add_argument("--motd", default="Welcome to SkyNetwork!")
    a = sub.add_parser("adduser")
    a.add_argument("cid", type=int)
    a.add_argument("name")
    a.add_argument("password")
    a.add_argument("--rating", default="OBS", choices=RATINGS)
    r = sub.add_parser("rating")
    r.add_argument("cid", type=int)
    r.add_argument("rating", choices=RATINGS)
    for name in ("suspend", "unsuspend"):
        sub.add_parser(name).add_argument("cid", type=int)
    args = p.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if args.cmd == "serve":
        asyncio.run(_serve(args))
        return
    acc = Accounts(args.db)
    if args.cmd == "adduser":
        acc.create(args.cid, args.name, args.password, args.rating)
    elif args.cmd == "rating":
        acc.set_rating(args.cid, args.rating)
    else:
        acc.set_suspended(args.cid, args.cmd == "suspend")
    print("ok")


if __name__ == "__main__":
    main()
