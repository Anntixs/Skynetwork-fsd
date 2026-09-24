// SkyNetwork FSD server: classic FSD text protocol over TCP plus an HTTP JSON data feed.
#pragma once
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "accounts.h"

namespace skynet {

struct FsdConfig {
    std::string host = "0.0.0.0";
    uint16_t port = 6809;
    uint16_t http_port = 8080;
    std::string server_name = "SKYNET";
    std::vector<std::string> motd = {"Welcome to SkyNetwork!"};
    // How often connected members are re-checked against the database: a member suspended (or an
    // ATC whose rating was lowered) on the website is disconnected within this time.
    int account_check_ms = 10000;
};

enum class Role { None, Pilot, Atc };

struct Conn {
    int fd = -1;
    bool http = false;
    bool closing = false;  // close once the output buffer is flushed
    std::string ip, in, out;
    int64_t connected_ms = 0, last_rx_ms = 0;
    time_t logon_time = 0;

    Role role = Role::None;
    std::string callsign, sim_or_client;
    Member member;
    int session_rating = 0;
    int protocol = 0;

    bool has_pos = false;
    double lat = 0, lon = 0;
    int alt = 0, gs = 0;
    int heading = -1;  // degrees, from the position packet's PBH field; -1 until known
    bool on_ground = false;
    std::string squawk = "2000", transponder = "S";
    double frequency = 0;  // ATC primary frequency in MHz
    int facility = 0, vis_range = 0;
    std::string flightplan;  // last $FP packet body (after "$FP<callsign>:")

    double range_nm() const;
};

class FsdServer {
public:
    FsdServer(Accounts& accounts, FsdConfig cfg);
    ~FsdServer();
    void bind();
    void run();  // blocks forever
    void stop() { running_ = false; }
    uint16_t port() const;
    uint16_t http_port() const;

private:
    void accept_on(int lfd, bool http);
    void on_readable(Conn& c);
    void on_line(Conn& c, const std::string& line);
    void on_http(Conn& c);
    void handle_login(Conn& c, char kind, const std::vector<std::string>& f);
    void handle_packet(Conn& c, const std::string& head, const std::vector<std::string>& f);
    void handle_text(Conn& c, const std::vector<std::string>& f, const std::string& raw);
    void handle_client_query(Conn& c, const std::vector<std::string>& f, const std::string& raw);
    // Supervisor commands ($CQ<cs>:SERVER:KILL|FIND|WHOIS|WARN|STAFF|ONLINE:...). True if `type` is one.
    bool handle_staff_command(Conn& c, const std::string& type, const std::vector<std::string>& f);
    void server_text(Conn& c, const std::string& text);

    void send(Conn& c, const std::string& line);
    void send_error(Conn& c, int code, const std::string& param, const std::string& text);
    void broadcast(const std::string& line, const Conn* except = nullptr);
    void broadcast_near(Conn& src, const std::string& line);
    bool in_range(const Conn& a, const Conn& b) const;
    Conn* find(const std::string& callsign);
    void drop(Conn& c, bool announce = true);
    void check_accounts();
    std::string data_feed_json() const;

    Accounts& accounts_;
    FsdConfig cfg_;
    int listen_fd_ = -1, http_fd_ = -1;
    bool running_ = true;
    int64_t next_account_check_ms_ = 0;
    std::map<int, std::unique_ptr<Conn>> conns_;
};

}  // namespace skynet
