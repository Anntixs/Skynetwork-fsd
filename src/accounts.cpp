#include "accounts.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <algorithm>
#include <ctime>
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

const char* staff_level_name(int level) {
    static const char* names[] = {"", "FSUP", "SUP", "ADM"};
    return level >= 0 && level <= 3 ? names[level] : "";
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
        " suspended INTEGER NOT NULL DEFAULT 0);"
        // Shared with the website, which creates them the same way.
        "CREATE TABLE IF NOT EXISTS staff_roles ("
        " cid INTEGER NOT NULL, role TEXT NOT NULL, PRIMARY KEY (cid, role));"
        "CREATE TABLE IF NOT EXISTS audit_log ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, actor_cid INTEGER NOT NULL, action TEXT NOT NULL,"
        " target TEXT NOT NULL DEFAULT '', details TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL)";
    if (sqlite3_exec(db_, schema, nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(db_));
    // Staff ranks used to live in the rating column. Move them to their own column once; the
    // website (sharing this database) does the same, whichever starts first.
    if (sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(db_));
    bool has_staff = false;
    {
        Stmt st(db_, "SELECT COUNT(*) FROM pragma_table_info('members') WHERE name = 'staff_rank'");
        has_staff = sqlite3_step(st.s) == SQLITE_ROW && sqlite3_column_int(st.s, 0) > 0;
    }
    const char* migrate =
        "ALTER TABLE members ADD COLUMN staff_rank INTEGER NOT NULL DEFAULT 0;"
        "UPDATE members SET staff_rank = rating, rating = 1 WHERE rating >= 11;";
    if (!has_staff && sqlite3_exec(db_, migrate, nullptr, nullptr, nullptr) != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db_);
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        throw std::runtime_error(err);
    }
    sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
}

Accounts::~Accounts() { sqlite3_close(db_); }

bool Accounts::create(int cid, const std::string& name, const std::string& password, int rating) {
    unsigned char salt[kSaltLen];
    RAND_bytes(salt, kSaltLen);
    auto hash = derive(password, salt);
    bool staff = rating >= SUP;
    Stmt st(db_, "INSERT INTO members (cid, name, rating, staff_rank, salt, hash) VALUES (?,?,?,?,?,?)");
    sqlite3_bind_int(st.s, 1, cid);
    sqlite3_bind_text(st.s, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st.s, 3, staff ? OBS : rating);
    sqlite3_bind_int(st.s, 4, staff ? rating : 0);
    sqlite3_bind_blob(st.s, 5, salt, kSaltLen, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st.s, 6, hash.data(), kHashLen, SQLITE_TRANSIENT);
    return sqlite3_step(st.s) == SQLITE_DONE;
}

bool Accounts::set_rating(int cid, int rating) {
    if (rating >= SUP) return set_staff(cid, rating);
    Stmt st(db_, "UPDATE members SET rating=? WHERE cid=?");
    sqlite3_bind_int(st.s, 1, rating);
    sqlite3_bind_int(st.s, 2, cid);
    return sqlite3_step(st.s) == SQLITE_DONE && sqlite3_changes(db_) == 1;
}

bool Accounts::set_staff(int cid, int rank) {
    if (rank != 0 && rank != SUP && rank != ADM) return false;
    Stmt st(db_, "UPDATE members SET staff_rank=? WHERE cid=?");
    sqlite3_bind_int(st.s, 1, rank);
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

bool Accounts::set_facility_supervisor(int cid, bool on) {
    if (!lookup(cid)) return false;
    Stmt st(db_, on ? "INSERT OR IGNORE INTO staff_roles (cid, role) VALUES (?, 'fsup')"
                    : "DELETE FROM staff_roles WHERE cid=? AND role='fsup'");
    sqlite3_bind_int(st.s, 1, cid);
    return sqlite3_step(st.s) == SQLITE_DONE;
}

bool Accounts::is_facility_supervisor(int cid) {
    Stmt st(db_, "SELECT 1 FROM staff_roles WHERE cid=? AND role='fsup'");
    sqlite3_bind_int(st.s, 1, cid);
    return sqlite3_step(st.s) == SQLITE_ROW;
}

void Accounts::audit(int actor_cid, const std::string& action, const std::string& target, const std::string& details) {
    try {
        Stmt st(db_, "INSERT INTO audit_log (actor_cid, action, target, details, created_at) VALUES (?,?,?,?,?)");
        sqlite3_bind_int(st.s, 1, actor_cid);
        sqlite3_bind_text(st.s, 2, action.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st.s, 3, target.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st.s, 4, details.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st.s, 5, static_cast<sqlite3_int64>(time(nullptr)));
        sqlite3_step(st.s);
    } catch (const std::exception&) {
    }
}

std::optional<Member> Accounts::authenticate(int cid, const std::string& password) {
    Stmt st(db_, "SELECT name, rating, salt, hash, suspended, staff_rank FROM members WHERE cid=?");
    sqlite3_bind_int(st.s, 1, cid);
    if (sqlite3_step(st.s) != SQLITE_ROW) return std::nullopt;
    if (sqlite3_column_bytes(st.s, 2) != kSaltLen || sqlite3_column_bytes(st.s, 3) != kHashLen)
        return std::nullopt;
    auto salt = static_cast<const unsigned char*>(sqlite3_column_blob(st.s, 2));
    auto stored = sqlite3_column_blob(st.s, 3);
    auto hash = derive(password, salt);
    if (CRYPTO_memcmp(hash.data(), stored, kHashLen) != 0) return std::nullopt;
    Member m;
    m.cid = cid;
    m.name = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
    m.controller_rating = sqlite3_column_int(st.s, 1);
    m.staff_rank = sqlite3_column_int(st.s, 5);
    m.rating = std::max(m.controller_rating, m.staff_rank);
    m.suspended = sqlite3_column_int(st.s, 4) != 0;
    m.facility_supervisor = is_facility_supervisor(cid);
    return m;
}

std::optional<Member> Accounts::lookup(int cid) {
    Stmt st(db_, "SELECT name, rating, suspended, staff_rank FROM members WHERE cid=?");
    sqlite3_bind_int(st.s, 1, cid);
    if (sqlite3_step(st.s) != SQLITE_ROW) return std::nullopt;
    Member m;
    m.cid = cid;
    m.name = reinterpret_cast<const char*>(sqlite3_column_text(st.s, 0));
    m.controller_rating = sqlite3_column_int(st.s, 1);
    m.staff_rank = sqlite3_column_int(st.s, 3);
    m.rating = std::max(m.controller_rating, m.staff_rank);
    m.suspended = sqlite3_column_int(st.s, 2) != 0;
    m.facility_supervisor = is_facility_supervisor(cid);
    return m;
}

}  // namespace skynet
