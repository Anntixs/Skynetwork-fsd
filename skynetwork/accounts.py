"""Member accounts stored in SQLite with PBKDF2 password hashes."""
import hashlib
import hmac
import os
import sqlite3

RATINGS = ["OBS", "S1", "S2", "S3", "C1", "C3", "I1", "I3", "SUP", "ADM"]
_ITER = 200_000


def _hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITER)


class Accounts:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS members ("
            " cid INTEGER PRIMARY KEY, name TEXT NOT NULL,"
            " rating TEXT NOT NULL DEFAULT 'OBS',"
            " salt BLOB NOT NULL, hash BLOB NOT NULL,"
            " suspended INTEGER NOT NULL DEFAULT 0)"
        )
        self.db.commit()

    def create(self, cid: int, name: str, password: str, rating: str = "OBS") -> None:
        if rating not in RATINGS:
            raise ValueError(f"unknown rating {rating}")
        salt = os.urandom(16)
        self.db.execute(
            "INSERT INTO members (cid, name, rating, salt, hash) VALUES (?,?,?,?,?)",
            (cid, name, rating, salt, _hash(password, salt)),
        )
        self.db.commit()

    def set_rating(self, cid: int, rating: str) -> None:
        if rating not in RATINGS:
            raise ValueError(f"unknown rating {rating}")
        self.db.execute("UPDATE members SET rating=? WHERE cid=?", (rating, cid))
        self.db.commit()

    def set_suspended(self, cid: int, suspended: bool) -> None:
        self.db.execute("UPDATE members SET suspended=? WHERE cid=?", (int(suspended), cid))
        self.db.commit()

    def authenticate(self, cid, password):
        """Return {"cid", "name", "rating"} or None."""
        try:
            cid = int(cid)
        except (TypeError, ValueError):
            return None
        row = self.db.execute(
            "SELECT name, rating, salt, hash, suspended FROM members WHERE cid=?", (cid,)
        ).fetchone()
        if not row or not isinstance(password, str):
            return None
        name, rating, salt, stored, suspended = row
        if suspended or not hmac.compare_digest(_hash(password, salt), stored):
            return None
        return {"cid": cid, "name": name, "rating": rating}
