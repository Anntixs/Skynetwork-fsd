#include "accounts.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <stdexcept>
#include <vector>

namespace skynet {
namespace {

constexpr int kIterations = 200000;
constexpr int kSaltLen = 16;
constexpr int kHashLen = 32;
const char* kNames[] = {"", "OBS", "S1", "S2", "S3", "C1", "C2", "C3", "I1", "I2", "I3", "SUP", "ADM"};

std::vector<unsigned char> derive(const std::string& password, const unsigned char* salt) {
    std::vector<unsigned char> out(kHashLen);
    PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt, kSaltLen,
                      kIterations, EVP_sha256(), kHashLen, out.data());
    return out;
}

struct Stmt {
    sqlite3_stmt* s = nullptr;
    Stmt(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &s, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db));
    }
    ~Stmt() { sqlite3_finalize(s); }
};

}  // namespace

const char* rating_name(int rating) {
    return (rating >= OBS && rating <= ADM) ? kNames[rating] : "?";
}

int rating_from_name(const std::string& name) {
    for (int r = OBS; r <= ADM; ++r)
        if (name == kNames[r]) return r;
    return 0;
}

Accounts::Accounts(const std::string& path) {
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK)
        throw std::runtime_error("cannot open database " + path);
    sqlite3_busy_timeout(db_, 2000);
    const char* schema =
        "CREATE TABLE IF NOT EXISTS members ("
        " cid INTEGER PRIMARY KEY, name TEXT NOT NULL,"
        " rating INTEGER NOT NULL DEFAULT 1,"
        " salt BLOB NOT NULL, hash BLOB NOT NULL,"
        " suspended INTEGER NOT NULL DEFAULT 0)";
    if (sqlite3_exec(db_, schema, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(db_));
}

Accounts::~Accounts() { sqlite3_close(db_); }

bool Accounts::create(int cid, const std::string& name, const std::string& password, int rating) {
    unsigned char salt[kSaltLen];
    RAND_bytes(salt, kSaltLen);
    auto hash = derive(password, salt);
    Stmt st(db_, "INSERT INTO members (cid, name, rating, salt, hash) VALUES (?,?,?,?,?)");
    sqlite3_bind_int(st.s, 1, cid);
    sqlite3_bind_text(st.s, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st.s, 3, rating);
    sqlite3_bind_blob(st.s, 4, salt, kSaltLen, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st.s, 5, hash.data(), kHashLen, SQLITE_TRANSIENT);
    return sqlite3_step(st.s) == SQLITE_DONE;
}

bool Accounts::set_rating(int cid, int rating) {
    Stmt st(db_, "UPDATE members SET rating=? WHERE cid=?");
    sqlite3_bind_int(st.s, 1, rating);
    sqlite3_bind_int(st.s, 2, cid);
    return sqlite3_step(st.s) == SQLITE_DONE && sqlite3_changes(db_) == 1;
}

bool Accounts::set_password(int cid, const std::string& password) {
    unsigned char salt[kSaltLen];
    RAND_bytes(salt, kSaltLen);
    auto hash = derive(password, salt);
    Stmt st(db_, "UPDATE members SET salt=?, hash=? WHERE cid=?");
    sqlite3_bind_blob(st.s, 1, salt, kSaltLen, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st.s, 2, hash.data(), kHashLen, SQLITE_TRANSIENT);
    sqlite3_bind_int(st.s, 3, cid);
    return sqlite3_step(st.s) == SQLITE_DONE && sqlite3_changes(db_) == 1;
}

bool Accounts::set_suspended(int cid, bool suspended) {
    Stmt st(db_, "UPDATE members SET suspended=? WHERE cid=?");
    sqlite3_bind_int(st.s, 1, suspended ? 1 : 0);
    sqlite3_bind_int(st.s, 2, cid);
    return sqlite3_step(st.s) == SQLITE_DONE && sqlite3_changes(db_) == 1;
}

std::optional<Member> Accounts::authenticate(int cid, const std::string& password) {
    Stmt st(db_, "SELECT name, rating, salt, hash, suspended FROM members WHERE cid=?");
    sqlite3_bind_int(st.s, 1, cid);
    if (sqlite3_step(st.s) != SQLITE_ROW) return std::nullopt;
    if (sqlite3_column_bytes(st.s, 2) != kSaltLen || sqlite3_column_bytes(st.s, 3) != kHashLen)
        return std::nullopt;
    auto salt = static_cast<const unsigned char*>(sqlite3_column_blob(st.s, 2));
    auto stored = sqlite3_column_blob(st.s, 3);
    auto hash = derive(password, salt);
    if (sqlite3_column_int(st.s, 4) != 0 || CRYPTO_memcmp(hash.data(), stored, kHashLen) != 0)
        return std::nullopt;
    Member m;
    m.cid = cid;
    m.name = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
    m.rating = sqlite3_column_int(st.s, 1);
    return m;
}

}  // namespace skynet
