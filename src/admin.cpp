// skynet-admin: manage network members.
#include <cstdio>
#include <cstring>
#include <string>

#include "accounts.h"

using namespace skynet;

static int usage() {
    std::fprintf(stderr,
                 "usage: skynet-admin [--db FILE] COMMAND\n"
                 "  adduser CID NAME PASSWORD [RATING]\n"
                 "  rating CID RATING        controller rating: OBS S1 S2 S3 C1 C2 C3 I1 I2 I3\n"
                 "                           (SUP or ADM here sets the staff rank, as 'staff')\n"
                 "  staff CID RANK           staff rank: SUP ADM NONE\n"
                 "  fsup CID on|off          facility supervisor\n"
                 "  passwd CID PASSWORD\n"
                 "  suspend CID | unsuspend CID\n");
    return 2;
}

int main(int argc, char** argv) {
    std::string db = "skynetwork.db";
    int i = 1;
    if (argc > 2 && std::strcmp(argv[1], "--db") == 0) {
        db = argv[2];
        i = 3;
    }
    if (argc - i < 2) return usage();
    std::string cmd = argv[i];
    int cid = std::atoi(argv[i + 1]);
    if (cid <= 0) return usage();
    Accounts acc(db);
    bool ok = false;
    if (cmd == "adduser" && argc - i >= 4) {
        int rating = argc - i >= 5 ? rating_from_name(argv[i + 4]) : OBS;
        ok = rating && acc.create(cid, argv[i + 2], argv[i + 3], rating);
    } else if (cmd == "rating" && argc - i >= 3) {
        int rating = rating_from_name(argv[i + 2]);
        ok = rating && acc.set_rating(cid, rating);
    } else if (cmd == "staff" && argc - i >= 3) {
        std::string rank = argv[i + 2];
        int r = rank == "NONE" ? 0 : rating_from_name(rank);
        ok = (r == 0 || r >= SUP) && acc.set_staff(cid, r);
    } else if (cmd == "fsup" && argc - i >= 3) {
        std::string v = argv[i + 2];
        ok = (v == "on" || v == "off") && acc.set_facility_supervisor(cid, v == "on");
    } else if (cmd == "passwd" && argc - i >= 3) {
        ok = acc.set_password(cid, argv[i + 2]);
    } else if (cmd == "suspend" || cmd == "unsuspend") {
        ok = acc.set_suspended(cid, cmd == "suspend");
    } else {
        return usage();
    }
    std::puts(ok ? "ok" : "failed");
    return ok ? 0 : 1;
}
