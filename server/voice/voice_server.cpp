#include "voice_server.h"

#include <openssl/rand.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "geo.h"
#include "net.h"

namespace skynet {
namespace {

constexpr int64_t kSessionTimeoutMs = 60000;

// Bounds-checked big-endian reader.
struct Reader {
    const uint8_t* p;
    size_t left;
    bool ok = true;

    bool need(size_t n) {
        if (left < n) ok = false;
        return ok;
    }
    uint8_t u8() {
        if (!need(1)) return 0;
        --left;
        return *p++;
    }
    uint32_t u32() {
        if (!need(4)) return 0;
        uint32_t v = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
        p += 4, left -= 4;
        return v;
    }
    double f64() {
        if (!need(8)) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
        p += 8, left -= 8;
        double d;
        std::memcpy(&d, &v, 8);
        return d;
    }
    std::string str() {
        uint8_t n = u8();
        if (!need(n)) return {};
        std::string s(reinterpret_cast<const char*>(p), n);
        p += n, left -= n;
        return s;
    }
};

struct Writer {
    std::vector<uint8_t> b;
    explicit Writer(uint8_t type) : b{'S', 'K', voice::kVersion, type} {}
    void u8(uint8_t v) { b.push_back(v); }
    void u32(uint32_t v) {
        for (int s = 24; s >= 0; s -= 8) b.push_back(uint8_t(v >> s));
    }
    void f32(float f) {
        uint32_t v;
        std::memcpy(&v, &f, 4);
        u32(v);
    }
    void str(const std::string& s) {
        u8(uint8_t(std::min<size_t>(s.size(), 255)));
        b.insert(b.end(), s.begin(), s.begin() + std::min<size_t>(s.size(), 255));
    }
};

bool same_addr(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

}  // namespace

VoiceServer::VoiceServer(Accounts& accounts, std::string host, uint16_t port)
    : accounts_(accounts), host_(std::move(host)), port_(port) {}

VoiceServer::~VoiceServer() {
    if (fd_ >= 0) close(fd_);
}

void VoiceServer::bind() { fd_ = bind_udp(host_, port_); }
uint16_t VoiceServer::port() const { return local_port(fd_); }

void VoiceServer::run() {
    uint8_t buf[voice::kMaxDatagram + 1];
    int64_t last_sweep = now_ms();
    for (;;) {
        pollfd pfd{fd_, POLLIN, 0};
        if (poll(&pfd, 1, 1000) < 0 && errno != EINTR) break;
        if (pfd.revents & POLLIN) {
            for (;;) {
                sockaddr_in from{};
                socklen_t flen = sizeof from;
                ssize_t n = recvfrom(fd_, buf, sizeof buf, 0, reinterpret_cast<sockaddr*>(&from), &flen);
                if (n < 0) break;
                if (size_t(n) <= voice::kMaxDatagram) on_datagram(buf, size_t(n), from);
            }
        }
        int64_t now = now_ms();
        if (now - last_sweep > 5000) {
            last_sweep = now;
            for (auto it = sessions_.begin(); it != sessions_.end();) {
                if (now - it->second.last_rx_ms > kSessionTimeoutMs) {
                    std::fprintf(stderr, "voice: %s timed out\n", it->second.callsign.c_str());
                    it = sessions_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }
}

void VoiceServer::send_to(const sockaddr_in& to, const std::vector<uint8_t>& pkt) {
    sendto(fd_, pkt.data(), pkt.size(), 0, reinterpret_cast<const sockaddr*>(&to), sizeof to);
}

VoiceSession* VoiceServer::session_for(uint32_t token, const sockaddr_in& from) {
    auto it = sessions_.find(token);
    if (it == sessions_.end() || !same_addr(it->second.addr, from)) return nullptr;
    it->second.last_rx_ms = now_ms();
    return &it->second;
}

void VoiceServer::on_datagram(const uint8_t* data, size_t len, const sockaddr_in& from) {
    if (len < 4 || data[0] != 'S' || data[1] != 'K' || data[2] != voice::kVersion) return;
    uint8_t type = data[3];
    const uint8_t* p = data + 4;
    len -= 4;
    if (type == voice::AUTH) return on_auth(p, len, from);

    Reader r{p, len};
    uint32_t token = r.u32();
    if (!r.ok) return;
    VoiceSession* s = session_for(token, from);
    if (!s) return;

    switch (type) {
        case voice::TRANSCEIVERS: {
            uint8_t n = r.u8();
            if (n > voice::kMaxTransceivers) return;
            std::vector<Transceiver> list;
            for (uint8_t i = 0; i < n; ++i) {
                Transceiver t{r.u8(), r.u32(), r.f64(), r.f64(), r.f64()};
                if (!r.ok || !(std::fabs(t.lat) <= 90) || !(std::fabs(t.lon) <= 180) ||
                    !(t.alt_ft > -2000 && t.alt_ft < 100000))
                    return;
                list.push_back(t);
            }
            s->transceivers = std::move(list);
            break;
        }
        case voice::AUDIO:
            on_audio(*s, r.p, r.left);
            break;
        case voice::KEEPALIVE:
            send_to(from, Writer(voice::KEEPALIVE_ACK).b);
            break;
        case voice::BYE:
            std::fprintf(stderr, "voice: %s left\n", s->callsign.c_str());
            sessions_.erase(token);
            break;
    }
}

void VoiceServer::on_auth(const uint8_t* p, size_t len, const sockaddr_in& from) {
    Reader r{p, len};
    int cid = int(r.u32());
    std::string callsign = r.str();
    std::string password = r.str();
    auto fail = [&](const char* reason) {
        Writer w(voice::AUTH_FAIL);
        w.str(reason);
        send_to(from, w.b);
    };
    if (!r.ok || callsign.empty() || callsign.size() > 12) return fail("malformed");
    for (auto& ch : callsign) ch = char(std::toupper(static_cast<unsigned char>(ch)));
    auto member = accounts_.authenticate(cid, password);
    if (!member) return fail("invalid credentials");

    // One voice session per callsign; the same member may reconnect and replace it.
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it->second.callsign != callsign) continue;
        if (it->second.cid != cid) return fail("callsign in use");
        sessions_.erase(it);
        break;
    }
    uint32_t token = 0;
    while (token == 0 || sessions_.count(token)) RAND_bytes(reinterpret_cast<unsigned char*>(&token), 4);
    sessions_[token] = VoiceSession{token, cid, callsign, from, now_ms(), {}};
    std::fprintf(stderr, "voice: %s (%d) connected\n", callsign.c_str(), cid);
    Writer w(voice::AUTH_OK);
    w.u32(token);
    send_to(from, w.b);
}

// AUDIO body (after token): u32 seq, u8 last, u8 n, n * tx_id, opus payload.
void VoiceServer::on_audio(VoiceSession& s, const uint8_t* p, size_t len) {
    Reader r{p, len};
    uint32_t seq = r.u32();
    uint8_t last = r.u8();
    uint8_t n = r.u8();
    if (!r.ok || n > voice::kMaxTransceivers) return;
    std::vector<const Transceiver*> tx;
    for (uint8_t i = 0; i < n; ++i) {
        uint8_t id = r.u8();
        for (const auto& t : s.transceivers)
            if (t.id == id) tx.push_back(&t);
    }
    if (!r.ok || tx.empty()) return;
    const uint8_t* opus = r.p;
    size_t opus_len = r.left;

    for (auto& [tok, other] : sessions_) {
        if (tok == s.token) continue;
        Writer w(voice::AUDIO_RX);
        w.u32(seq);
        w.u8(last);
        w.str(s.callsign);
        size_t count_pos = w.b.size();
        w.u8(0);
        uint8_t count = 0;
        for (const auto& rx : other.transceivers) {
            float best = 0;
            for (const Transceiver* t : tx) {
                if (t->freq_hz != rx.freq_hz) continue;
                double range = radio_horizon_nm(t->alt_ft, rx.alt_ft);
                double d = distance_nm(t->lat, t->lon, rx.lat, rx.lon);
                if (d <= range) best = std::max(best, float(1.0 - d / range));
            }
            if (best > 0) {
                w.u32(rx.freq_hz);
                w.f32(best);
                ++count;
            }
        }
        if (count == 0) continue;
        w.b[count_pos] = count;
        w.b.insert(w.b.end(), opus, opus + opus_len);
        send_to(other.addr, w.b);
    }
}

}  // namespace skynet
