#include "fsd_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>

#include "geo.h"
#include "net.h"

namespace skynet {
namespace {

constexpr size_t kMaxLine = 4096;
constexpr size_t kMaxOutBuffer = 1 << 20;
constexpr int64_t kLoginTimeoutMs = 30000;
constexpr int64_t kIdleTimeoutMs = 180000;
constexpr int kPilotRangeNm = 60;
constexpr int kMaxAtcRangeNm = 600;

// FSD error codes.
enum {
    ERR_CSINUSE = 1, ERR_CSINVALID = 2, ERR_REGISTERED = 3, ERR_SYNTAX = 4, ERR_SRCINVALID = 5,
    ERR_CIDINVALID = 6, ERR_NOSUCHCS = 7, ERR_NOFP = 8, ERR_NOWEATHER = 9, ERR_REVISION = 10,
    ERR_LEVEL = 11, ERR_SERVFULL = 12, ERR_CSSUSPEND = 13,
};

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char ch : s) {
        if (ch == sep) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += ch;
        }
    }
    out.push_back(cur);
    return out;
}

std::string upper(std::string s) {
    for (auto& ch : s) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    return s;
}

bool valid_callsign(const std::string& cs) {
    if (cs.size() < 2 || cs.size() > 12) return false;
    for (char ch : cs)
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_' && ch != '-') return false;
    return cs != "SERVER";
}

bool parse_int(const std::string& s, int& out) {
    char* end = nullptr;
    errno = 0;
    long v = std::strtol(s.c_str(), &end, 10);
    if (s.empty() || *end || errno) return false;
    out = static_cast<int>(v);
    return true;
}

bool parse_double(const std::string& s, double& out) {
    char* end = nullptr;
    double v = std::strtod(s.c_str(), &end);
    if (s.empty() || *end || !std::isfinite(v)) return false;
    out = v;
    return true;
}

std::string json_str(const std::string& s) {
    std::string o = "\"";
    for (unsigned char ch : s) {
        switch (ch) {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (ch < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", ch);
                    o += buf;
                } else {
                    o += static_cast<char>(ch);
                }
        }
    }
    return o + "\"";
}

std::string fmt_double(double v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%.6f", v);
    return buf;
}

void log(const char* fmt, const std::string& a, const std::string& b = "") {
    char ts[32];
    time_t t = time(nullptr);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", gmtime(&t));
    std::fprintf(stderr, "%s ", ts);
    std::fprintf(stderr, fmt, a.c_str(), b.c_str());
    std::fputc('\n', stderr);
}

}  // namespace

double Conn::range_nm() const {
    if (role == Role::Atc) return vis_range;
    return kPilotRangeNm;
}

FsdServer::FsdServer(Accounts& accounts, FsdConfig cfg) : accounts_(accounts), cfg_(std::move(cfg)) {}

FsdServer::~FsdServer() {
    for (auto& [fd, c] : conns_) close(fd);
    if (listen_fd_ >= 0) close(listen_fd_);
    if (http_fd_ >= 0) close(http_fd_);
}

void FsdServer::bind() {
    listen_fd_ = listen_tcp(cfg_.host, cfg_.port);
    http_fd_ = listen_tcp(cfg_.host, cfg_.http_port);
}

uint16_t FsdServer::port() const { return local_port(listen_fd_); }
uint16_t FsdServer::http_port() const { return local_port(http_fd_); }

void FsdServer::run() {
    std::vector<pollfd> pfds;
    while (running_) {
        pfds.clear();
        pfds.push_back({listen_fd_, POLLIN, 0});
        pfds.push_back({http_fd_, POLLIN, 0});
        for (auto& [fd, c] : conns_)
            pfds.push_back({fd, static_cast<short>(POLLIN | (c->out.empty() ? 0 : POLLOUT)), 0});

        if (poll(pfds.data(), pfds.size(), 1000) < 0 && errno != EINTR) break;

        if (pfds[0].revents & POLLIN) accept_on(listen_fd_, false);
        if (pfds[1].revents & POLLIN) accept_on(http_fd_, true);

        for (size_t i = 2; i < pfds.size(); ++i) {
            auto it = conns_.find(pfds[i].fd);
            if (it == conns_.end()) continue;
            Conn& c = *it->second;
            if (pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) c.closing = true, c.out.clear();
            if (!c.closing && (pfds[i].revents & POLLIN)) on_readable(c);
            if (!c.out.empty() && (pfds[i].revents & POLLOUT)) {
                ssize_t n = ::send(c.fd, c.out.data(), c.out.size(), MSG_NOSIGNAL);
                if (n > 0) c.out.erase(0, n);
                else if (n < 0 && errno != EAGAIN) c.closing = true, c.out.clear();
            }
        }

        // Timeouts and cleanup.
        int64_t now = now_ms();
        if (now >= next_account_check_ms_) {
            check_accounts();
            next_account_check_ms_ = now + cfg_.account_check_ms;
        }
        std::vector<int> dead;
        for (auto& [fd, c] : conns_) {
            if (!c->closing) {
                bool login_to = c->role == Role::None && now - c->connected_ms > kLoginTimeoutMs;
                if (login_to || now - c->last_rx_ms > kIdleTimeoutMs) {
                    if (!c->http && c->role != Role::None) log("%s timed out", c->callsign);
                    drop(*c);
                }
            }
            if (c->closing && c->out.empty()) dead.push_back(fd);
        }
        for (int fd : dead) {
            close(fd);
            conns_.erase(fd);
        }
    }
}

void FsdServer::accept_on(int lfd, bool http) {
    for (;;) {
        sockaddr_in addr{};
        socklen_t len = sizeof addr;
        int fd = accept(lfd, reinterpret_cast<sockaddr*>(&addr), &len);
        if (fd < 0) return;
        set_nonblocking(fd);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        auto c = std::make_unique<Conn>();
        c->fd = fd;
        c->http = http;
        char ip[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof ip);
        c->ip = ip;
        c->connected_ms = c->last_rx_ms = now_ms();
        conns_[fd] = std::move(c);
    }
}

void FsdServer::on_readable(Conn& c) {
    char buf[8192];
    ssize_t n = recv(c.fd, buf, sizeof buf, 0);
    if (n == 0 || (n < 0 && errno != EAGAIN)) {
        drop(c);
        c.out.clear();
        return;
    }
    if (n < 0) return;
    c.last_rx_ms = now_ms();
    c.in.append(buf, n);

    if (c.http) {
        on_http(c);
        return;
    }
    size_t pos;
    while (!c.closing && (pos = c.in.find('\n')) != std::string::npos) {
        std::string line = c.in.substr(0, pos);
        c.in.erase(0, pos + 1);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) on_line(c, line);
    }
    if (c.in.size() > kMaxLine) {
        send_error(c, ERR_SYNTAX, "", "Line too long");
        drop(c);
    }
}

void FsdServer::on_line(Conn& c, const std::string& line) {
    std::string head;
    std::string body;
    if (line[0] == '@' || line[0] == '%') {
        head = line.substr(0, 1);
        body = line.substr(1);
    } else if ((line[0] == '#' || line[0] == '$') && line.size() >= 3) {
        head = line.substr(0, 3);
        body = line.substr(3);
    } else {
        send_error(c, ERR_SYNTAX, "", "Syntax error");
        return;
    }
    auto f = split(body, ':');

    if (c.role == Role::None) {
        if (head == "#AP" || head == "#AA") {
            handle_login(c, head[2], f);
        } else {
            send_error(c, ERR_SYNTAX, "", "Login required");
            drop(c);
        }
        return;
    }
    // '@' packets carry the callsign in the second field, all others in the first.
    const std::string& from = head == "@" ? (f.size() > 1 ? f[1] : "") : f[0];
    if (upper(from) != c.callsign) {
        send_error(c, ERR_SRCINVALID, from, "Invalid source callsign");
        return;
    }
    handle_packet(c, head, f);
}

// #AP<cs>:SERVER:<cid>:<password>:<rating>:<protocol>:<simtype>:<realname>
// #AA<cs>:SERVER:<realname>:<cid>:<password>:<rating>:<protocol>
void FsdServer::handle_login(Conn& c, char kind, const std::vector<std::string>& f) {
    bool pilot = kind == 'P';
    if (f.size() < 7) {
        send_error(c, ERR_SYNTAX, "", "Syntax error");
        drop(c);
        return;
    }
    std::string cs = upper(f[0]);
    const std::string& cid_s = pilot ? f[2] : f[3];
    const std::string& password = pilot ? f[3] : f[4];
    const std::string& rating_s = pilot ? f[4] : f[5];
    const std::string& proto_s = pilot ? f[5] : f[6];
    int cid = 0, rating = 0, proto = 0;

    auto fail = [&](int code, const std::string& text) {
        send_error(c, code, cs, text);
        drop(c, false);
    };
    if (!valid_callsign(cs)) return fail(ERR_CSINVALID, "Invalid callsign");
    if (!parse_int(cid_s, cid) || !parse_int(rating_s, rating) || !parse_int(proto_s, proto))
        return fail(ERR_SYNTAX, "Syntax error");
    if (proto < 9) return fail(ERR_REVISION, "Invalid protocol revision");
    auto member = accounts_.authenticate(cid, password);
    if (!member) return fail(ERR_CIDINVALID, "Invalid CID/password");
    if (member->suspended) return fail(ERR_CSSUSPEND, "CID suspended");
    if (member->email_unconfirmed)
        return fail(ERR_CIDINVALID, "Email not confirmed: open the link sent to your email when you registered");
    if (find(cs)) return fail(ERR_CSINUSE, "Callsign in use");
    if (!pilot && (rating < OBS || rating > member->rating))
        return fail(ERR_LEVEL, "Requested level too high");
    // Supervisor and administrator positions (XXX_SUP, XXX_ADM) need the staff rank.
    auto ends_with = [&](const char* suffix) {
        size_t n = std::strlen(suffix);
        return cs.size() >= n && cs.compare(cs.size() - n, n, suffix) == 0;
    };
    if ((ends_with("_SUP") && member->staff_rank < SUP) || (ends_with("_ADM") && member->staff_rank < ADM))
        return fail(ERR_LEVEL, "This position needs a supervisor or administrator rank");

    c.role = pilot ? Role::Pilot : Role::Atc;
    c.callsign = cs;
    c.member = *member;
    c.session_rating = pilot ? OBS : rating;
    c.protocol = proto;
    c.logon_time = time(nullptr);
    c.sim_or_client = pilot ? f[6] : "";
    if (pilot && f.size() > 7 && !f[7].empty()) c.member.name = f[7];
    if (!pilot && !f[2].empty()) c.member.name = f[2];

    log("%s connected from %s", cs, c.ip);
    for (const auto& line : cfg_.motd) send(c, "#TMSERVER:" + cs + ":" + line);
    // Announce the new client to everyone else (no password).
    if (pilot)
        broadcast("#AP" + cs + ":SERVER:" + std::to_string(cid) + "::1:" + proto_s + ":" + f[6] + ":" +
                      c.member.name, &c);
    else
        broadcast("#AA" + cs + ":SERVER:" + c.member.name + ":" + std::to_string(cid) + "::" + rating_s +
                      ":" + proto_s, &c);
}

void FsdServer::handle_packet(Conn& c, const std::string& head, const std::vector<std::string>& f) {
    std::string raw;  // original packet, used when relaying
    {
        std::ostringstream os;
        os << head;
        for (size_t i = 0; i < f.size(); ++i) os << (i ? ":" : "") << f[i];
        raw = os.str();
    }

    if (head == "@") {
        // @<mode>:<cs>:<squawk>:<rating>:<lat>:<lon>:<alt>:<gs>:<pbh>:<flags>
        if (c.role != Role::Pilot || f.size() < 8) return send_error(c, ERR_SYNTAX, "", "Syntax error");
        double lat, lon;
        int alt, gs;
        if (!parse_double(f[4], lat) || !parse_double(f[5], lon) || !parse_int(f[6], alt) ||
            !parse_int(f[7], gs) || std::fabs(lat) > 90 || std::fabs(lon) > 180)
            return send_error(c, ERR_SYNTAX, "", "Invalid position");
        c.has_pos = true;
        c.lat = lat, c.lon = lon, c.alt = alt, c.gs = gs;
        c.transponder = f[0].substr(0, 1);
        c.squawk = f[2].substr(0, 4);
        broadcast_near(c, raw);
    } else if (head == "%") {
        // %<cs>:<freq>:<facility>:<visrange>:<rating>:<lat>:<lon>:<alt>
        if (c.role != Role::Atc || f.size() < 7) return send_error(c, ERR_SYNTAX, "", "Syntax error");
        int freq, facility, range;
        double lat, lon;
        if (!parse_int(f[1], freq) || !parse_int(f[2], facility) || !parse_int(f[3], range) ||
            !parse_double(f[5], lat) || !parse_double(f[6], lon) || std::fabs(lat) > 90 || std::fabs(lon) > 180)
            return send_error(c, ERR_SYNTAX, "", "Invalid position");
        c.has_pos = true;
        c.lat = lat, c.lon = lon;
        c.frequency = 100.0 + freq / 1000.0;  // "18100" -> 118.100
        c.facility = facility;
        c.vis_range = std::max(0, std::min(range, kMaxAtcRangeNm));
        broadcast_near(c, raw);
    } else if (head == "#TM") {
        handle_text(c, f, raw);
    } else if (head == "#DP" || head == "#DA") {
        drop(c);
    } else if (head == "$FP") {
        if (c.role != Role::Pilot || f.size() < 17) return send_error(c, ERR_SYNTAX, "", "Syntax error");
        c.flightplan = raw.substr(3 + c.callsign.size() + 1);
        for (auto& [fd, o] : conns_)
            if (o.get() != &c && o->role == Role::Atc) send(*o, raw);
    } else if (head == "$AM") {
        // $AM<atc>:SERVER:<pilot>:<flight plan fields...> - controller amends a flight plan.
        if (c.role != Role::Atc || c.session_rating < S1 || f.size() < 17)
            return send_error(c, ERR_SYNTAX, "", "Syntax error");
        Conn* p = find(upper(f[2]));
        if (!p || p->role != Role::Pilot) return send_error(c, ERR_NOSUCHCS, f[2], "No such callsign");
        std::string body;
        for (size_t i = 3; i < f.size(); ++i) body += (i > 3 ? ":" : "") + f[i];
        p->flightplan = "*A:" + body;
        std::string fp = "$FP" + p->callsign + ":" + p->flightplan;
        for (auto& [fd, o] : conns_)
            if (o->role == Role::Atc) send(*o, fp);
    } else if (head == "$CQ") {
        handle_client_query(c, f, raw);
    } else if (head == "$PI") {
        if (f.size() < 2) return;
        if (upper(f[1]) == "SERVER") send(c, "$POSERVER:" + c.callsign + (f.size() > 2 ? ":" + f[2] : ""));
        else if (Conn* t = find(upper(f[1]))) send(*t, raw);
    } else {
        // Anything else addressed to a single callsign ($CR, $PO, #PC, $HO, #SB, ...) is relayed as-is.
        if (f.size() < 2) return;
        std::string to = upper(f[1]);
        if (to == "SERVER" || to == "*" || to.empty()) return;
        if (Conn* t = find(to)) send(*t, raw);
        else send_error(c, ERR_NOSUCHCS, f[1], "No such callsign");
    }
}

// #TM<from>:<to>:<text>. <to> is a callsign, "*" (broadcast, SUP+), "*S" (supervisors) or "@<freq>".
void FsdServer::handle_text(Conn& c, const std::vector<std::string>& f, const std::string& raw) {
    if (f.size() < 3) return send_error(c, ERR_SYNTAX, "", "Syntax error");
    std::string to = upper(f[1]);
    if (to == "*") {
        if (c.member.rating < SUP) return send_error(c, ERR_LEVEL, "", "Broadcast requires supervisor");
        broadcast(raw, &c);
    } else if (to == "*S") {
        // A call for a supervisor (.wallop). The sender is told whether anyone got it.
        int delivered = 0;
        for (auto& [fd, o] : conns_)
            if (o.get() != &c && o->role != Role::None && o->member.staff_level() >= 1) {
                send(*o, raw);
                delivered++;
            }
        send(c, "#TMSERVER:" + c.callsign + ":" +
                (delivered > 0 ? "Supervisor call sent, recipients: " + std::to_string(delivered)
                               : std::string("No supervisors are online right now. Try again later or contact support on the website")));
    } else if (to[0] == '@') {
        // Radio message: everyone within range of the sender.
        for (auto& [fd, o] : conns_)
            if (o.get() != &c && o->role != Role::None && in_range(c, *o)) send(*o, raw);
    } else if (Conn* t = find(to)) {
        send(*t, raw);
    } else {
        send_error(c, ERR_NOSUCHCS, f[1], "No such callsign");
    }
}

// $CQ<from>:<to>:<type>[:args]. Queries to SERVER are answered here, others are relayed.
void FsdServer::handle_client_query(Conn& c, const std::vector<std::string>& f, const std::string& raw) {
    if (f.size() < 3) return send_error(c, ERR_SYNTAX, "", "Syntax error");
    std::string to = upper(f[1]);
    if (to == "@94835") {
        // Shared controller data (assume, release, scratchpad, cleared level, squawk...): every other ATC client.
        if (c.role != Role::Atc) return send_error(c, ERR_LEVEL, "", "Controllers only");
        for (auto& [fd, o] : conns_)
            if (o.get() != &c && o->role == Role::Atc) send(*o, raw);
        return;
    }
    if (to != "SERVER") {
        if (Conn* t = find(to)) send(*t, raw);
        else if (to != "*") send_error(c, ERR_NOSUCHCS, f[1], "No such callsign");
        return;
    }
    const std::string& type = f[2];
    if (handle_staff_command(c, upper(type), f)) return;
    if (type == "FP" && f.size() > 3) {
        Conn* p = find(upper(f[3]));
        if (!p || p->role != Role::Pilot) return send_error(c, ERR_NOSUCHCS, f[3], "No such callsign");
        if (p->flightplan.empty()) return send_error(c, ERR_NOFP, p->callsign, "No flightplan");
        send(c, "$FP" + p->callsign + ":" + p->flightplan);
    } else if (type == "IP") {
        send(c, "$CRSERVER:" + c.callsign + ":IP:" + c.ip);
    } else if (type == "ATC") {
        send(c, std::string("$CRSERVER:") + c.callsign + ":ATC:" + (c.session_rating >= S1 ? "Y" : "N") + ":" +
                    c.callsign);
    }
}

void FsdServer::server_text(Conn& c, const std::string& text) { send(c, "#TMSERVER:" + c.callsign + ":" + text); }

namespace {

// Text after the first `from` fields, joined back (a reason may contain ':').
std::string join_from(const std::vector<std::string>& f, size_t from) {
    std::string out;
    for (size_t i = from; i < f.size(); ++i) out += (i > from ? ":" : "") + f[i];
    size_t b = out.find_first_not_of(' '), e = out.find_last_not_of(' ');
    return b == std::string::npos ? "" : out.substr(b, e - b + 1);
}

std::string hhmm(time_t t) {
    char buf[16];
    strftime(buf, sizeof buf, "%H:%Mz", gmtime(&t));
    return buf;
}

std::string role_text(const Conn& c) {
    if (c.role == Role::Pilot) return "pilot";
    std::string r = std::string("controller ") + rating_name(c.session_rating);
    if (c.member.staff_rank) r += std::string(", ") + rating_name(c.member.staff_rank);
    return r;
}

}  // namespace

// Commands for supervisors (SUP) and administrators (ADM). A supervisor acts only on members without a
// staff rank, an administrator on anyone but themselves.
bool FsdServer::handle_staff_command(Conn& c, const std::string& type, const std::vector<std::string>& f) {
    static const char* kTypes[] = {"KILL", "FIND", "WHOIS", "WARN", "STAFF", "ONLINE"};
    if (std::find(std::begin(kTypes), std::end(kTypes), type) == std::end(kTypes)) return false;
    int level = c.member.staff_level();
    if (level < 1) {
        send_error(c, ERR_LEVEL, "", "Supervisors only");
        return true;
    }
    // Target: a callsign, or a CID (digits) for WHOIS/FIND.
    auto target = [&]() -> Conn* {
        if (f.size() < 4 || f[3].empty()) return nullptr;
        std::string t = upper(f[3]);
        int cid = 0;
        if (type != "KILL" && type != "WARN" && parse_int(t, cid)) {
            for (auto& [fd, o] : conns_)
                if (o->role != Role::None && !o->closing && o->member.cid == cid) return o.get();
            return nullptr;
        }
        return find(t);
    };
    auto may_act_on = [&](const Conn& t) {
        if (&t == &c) return false;
        return level == 2 || t.member.staff_level() < level;
    };

    if (type == "KILL" || type == "WARN") {
        Conn* t = target();
        std::string text = join_from(f, 4);
        if (f.size() < 4 || text.empty()) {
            server_text(c, type == "KILL" ? "Usage: .kill CALLSIGN reason" : "Usage: .warn CALLSIGN text");
            return true;
        }
        if (!t) {
            send_error(c, ERR_NOSUCHCS, f[3], "No such callsign");
            return true;
        }
        if (!may_act_on(*t)) {
            server_text(c, "You cannot " + std::string(type == "KILL" ? "disconnect " : "warn ") + t->callsign +
                               ": they rank the same as you or higher");
            return true;
        }
        std::string who = t->callsign + " (CID " + std::to_string(t->member.cid) + ")";
        if (type == "WARN") {
            server_text(*t, "Warning from supervisor " + c.callsign + ": " + text);
            server_text(c, "Warning sent to " + t->callsign);
            accounts_.audit(c.member.cid, "network-warn", who, text + " (by " + c.callsign + ")");
            log("%s warned %s", c.callsign, t->callsign);
            return true;
        }
        server_text(*t, "You have been disconnected from the network by supervisor " + c.callsign + ". Reason: " + text);
        send(*t, "$!!SERVER:" + t->callsign + ":" + text);
        accounts_.audit(c.member.cid, "network-kill", who, text + " (by " + c.callsign + ")");
        log("%s disconnected by %s", t->callsign, c.callsign);
        drop(*t);
        server_text(c, who + " disconnected");
        return true;
    }
    if (type == "FIND" || type == "WHOIS") {
        Conn* t = target();
        if (!t) {
            if (f.size() < 4 || f[3].empty()) server_text(c, "Usage: ." + std::string(type == "FIND" ? "find" : "whois") + " CALLSIGN");
            else send_error(c, ERR_NOSUCHCS, f[3], "No such callsign");
            return true;
        }
        if (type == "FIND") {
            if (!t->has_pos) {
                server_text(c, t->callsign + " is online but has not sent a position yet");
                return true;
            }
            send(c, "$CRSERVER:" + c.callsign + ":FIND:" + t->callsign + ":" + fmt_double(t->lat) + ":" +
                        fmt_double(t->lon) + ":" + std::to_string(t->alt));
            return true;
        }
        std::string info = t->callsign + ": " + t->member.name + ", CID " + std::to_string(t->member.cid) + ", " +
                           role_text(*t) + ", online since " + hhmm(t->logon_time);
        if (t->role == Role::Pilot) {
            if (!t->sim_or_client.empty()) info += ", sim " + t->sim_or_client;
            auto fp = split(t->flightplan, ':');
            if (fp.size() > 8) info += ", " + fp[2] + " " + fp[4] + "-" + fp[8];
            if (t->has_pos) info += ", FL" + std::to_string(t->alt / 100) + " GS " + std::to_string(t->gs) + " sq " + t->squawk;
        } else if (t->frequency > 0) {
            char freq[16];
            std::snprintf(freq, sizeof freq, "%.3f", t->frequency);
            info += std::string(", ") + freq;
        }
        if (level == 2) info += ", IP " + t->ip;
        server_text(c, info);
        return true;
    }
    if (type == "STAFF") {
        std::string list;
        for (auto& [fd, o] : conns_)
            if (o->role != Role::None && !o->closing && o->member.staff_level() > 0)
                list += (list.empty() ? "" : ", ") + o->callsign + " (" + rating_name(o->member.staff_rank) + ")";
        server_text(c, "Staff online: " + list);
        return true;
    }
    // ONLINE: counts and the controllers.
    int pilots = 0;
    std::string atc;
    for (auto& [fd, o] : conns_) {
        if (o->role == Role::None || o->closing) continue;
        if (o->role == Role::Pilot) {
            pilots++;
        } else {
            char freq[16];
            std::snprintf(freq, sizeof freq, "%.3f", o->frequency);
            atc += (atc.empty() ? "" : ", ") + o->callsign + (o->frequency > 0 ? std::string(" ") + freq : "");
        }
    }
    server_text(c, "Online: " + std::to_string(pilots) + " pilots. Controllers: " + (atc.empty() ? "none" : atc));
    return true;
}

void FsdServer::on_http(Conn& c) {
    size_t end = c.in.find("\r\n\r\n");
    if (end == std::string::npos) end = c.in.find("\n\n");
    if (end == std::string::npos) {
        if (c.in.size() > kMaxLine) c.closing = true;
        return;
    }
    auto parts = split(c.in.substr(0, c.in.find_first_of("\r\n")), ' ');
    std::string path = parts.size() > 1 ? parts[1] : "";
    std::string status = "200 OK", body;
    if (parts[0] == "GET" && (path == "/" || path == "/data.json")) {
        body = data_feed_json();
    } else {
        status = "404 Not Found";
        body = "{\"error\":\"not found\"}";
    }
    c.out += "HTTP/1.1 " + status +
             "\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: " +
             std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    c.in.clear();
    c.closing = true;
}

std::string FsdServer::data_feed_json() const {
    std::string pilots, atc;
    for (auto& [fd, cp] : conns_) {
        const Conn& c = *cp;
        if (c.role == Role::None || c.closing) continue;
        std::string o = "{\"cid\":" + std::to_string(c.member.cid) + ",\"name\":" + json_str(c.member.name) +
                        ",\"callsign\":" + json_str(c.callsign) +
                        ",\"logon_time\":" + std::to_string(c.logon_time);
        if (c.has_pos) o += ",\"latitude\":" + fmt_double(c.lat) + ",\"longitude\":" + fmt_double(c.lon);
        if (c.role == Role::Pilot) {
            o += ",\"altitude\":" + std::to_string(c.alt) + ",\"groundspeed\":" + std::to_string(c.gs) +
                 ",\"transponder\":" + json_str(c.squawk) + ",\"flight_plan\":" +
                 (c.flightplan.empty() ? "null" : json_str(c.flightplan)) + "}";
            pilots += (pilots.empty() ? "" : ",") + o;
        } else {
            char freq[16];
            std::snprintf(freq, sizeof freq, "%.3f", c.frequency);
            o += std::string(",\"rating\":") + json_str(rating_name(c.session_rating)) +
                 ",\"frequency\":" + json_str(freq) + ",\"facility\":" + std::to_string(c.facility) +
                 ",\"visual_range\":" + std::to_string(c.vis_range) + "}";
            atc += (atc.empty() ? "" : ",") + o;
        }
    }
    return "{\"general\":{\"server\":" + json_str(cfg_.server_name) +
           ",\"update_timestamp\":" + std::to_string(time(nullptr)) + "},\"pilots\":[" + pilots +
           "],\"controllers\":[" + atc + "]}";
}

void FsdServer::send(Conn& c, const std::string& line) {
    if (c.closing) return;
    if (c.out.size() > kMaxOutBuffer) {  // client is not reading; cut it off
        drop(c);
        c.out.clear();
        return;
    }
    c.out += line;
    c.out += "\r\n";
}

void FsdServer::send_error(Conn& c, int code, const std::string& param, const std::string& text) {
    send(c, "$ERserver:" + (c.callsign.empty() ? std::string("unknown") : c.callsign) + ":" +
                (code < 10 ? "00" : "0") + std::to_string(code) + ":" + param + ":" + text);
}

void FsdServer::broadcast(const std::string& line, const Conn* except) {
    for (auto& [fd, o] : conns_)
        if (o.get() != except && o->role != Role::None) send(*o, line);
}

bool FsdServer::in_range(const Conn& a, const Conn& b) const {
    if (!a.has_pos || !b.has_pos) return false;
    return distance_nm(a.lat, a.lon, b.lat, b.lon) <= std::max(a.range_nm(), b.range_nm());
}

void FsdServer::broadcast_near(Conn& src, const std::string& line) {
    for (auto& [fd, o] : conns_)
        if (o.get() != &src && o->role != Role::None && in_range(src, *o)) send(*o, line);
}

Conn* FsdServer::find(const std::string& callsign) {
    for (auto& [fd, o] : conns_)
        if (o->role != Role::None && !o->closing && o->callsign == callsign) return o.get();
    return nullptr;
}

void FsdServer::check_accounts() {
    for (auto& [fd, c] : conns_) {
        if (c->closing || c->role == Role::None) continue;
        auto m = accounts_.lookup(c->member.cid);
        if (!m || m->suspended) {
            log("%s disconnected: CID %s suspended", c->callsign, std::to_string(c->member.cid));
            send_error(*c, ERR_CSSUSPEND, c->callsign, "CID suspended");
            drop(*c);
        } else if (c->role == Role::Atc && m->rating < c->session_rating) {
            log("%s disconnected: rating lowered to %s", c->callsign, rating_name(m->rating));
            send_error(*c, ERR_LEVEL, c->callsign, "Rating changed, reconnect");
            drop(*c);
        } else {
            c->member.rating = m->rating;
            c->member.staff_rank = m->staff_rank;
        }
    }
}

void FsdServer::drop(Conn& c, bool announce) {
    if (c.closing) return;
    c.closing = true;
    if (announce && c.role != Role::None) {
        log("%s disconnected", c.callsign);
        std::string bye = (c.role == Role::Pilot ? "#DP" : "#DA") + c.callsign + ":" + std::to_string(c.member.cid);
        for (auto& [fd, o] : conns_)
            if (o.get() != &c && o->role != Role::None && !o->closing) o->out += bye + "\r\n";
    }
    c.role = Role::None;
}

}  // namespace skynet
