// Member accounts: SQLite storage, PBKDF2-SHA256 password hashes.
#pragma once
#include <optional>
#include <string>

struct sqlite3;

namespace skynet {

// Controller ratings, numbered as in the classic FSD protocol.
enum Rating {
    OBS = 1, S1, S2, S3, C1, C2, C3, I1, I2, I3, SUP, ADM
};

const char* rating_name(int rating);
int rating_from_name(const std::string& name);  // 0 if unknown

struct Member {
    int cid = 0;
    std::string name;
    int rating = OBS;
    bool suspended = false;
};

class Accounts {
public:
    explicit Accounts(const std::string& path);
    ~Accounts();
    Accounts(const Accounts&) = delete;
    Accounts& operator=(const Accounts&) = delete;

    bool create(int cid, const std::string& name, const std::string& password, int rating);
    bool set_rating(int cid, int rating);
    bool set_password(int cid, const std::string& password);
    bool set_suspended(int cid, bool suspended);
    // The member if the password is right (check `suspended` before letting them in), else nothing.
    std::optional<Member> authenticate(int cid, const std::string& password);
    // Current state of an account (rating, suspension), without a password; nothing if deleted.
    std::optional<Member> lookup(int cid);

private:
    sqlite3* db_ = nullptr;
};

}  // namespace skynet
