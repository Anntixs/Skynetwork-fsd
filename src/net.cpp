#include "net.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <stdexcept>

namespace skynet {
namespace {

sockaddr_in make_addr(const std::string& host, uint16_t port) {
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1)
        throw std::runtime_error("bad address " + host);
    return a;
}

int bound_socket(int type, const std::string& host, uint16_t port) {
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) throw std::runtime_error("socket() failed");
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    auto a = make_addr(host, port);
    if (bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) < 0) {
        close(fd);
        throw std::runtime_error("cannot bind " + host + ":" + std::to_string(port));
    }
    set_nonblocking(fd);
    return fd;
}

}  // namespace

void set_nonblocking(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

int listen_tcp(const std::string& host, uint16_t port) {
    int fd = bound_socket(SOCK_STREAM, host, port);
    if (listen(fd, 128) < 0) throw std::runtime_error("listen() failed");
    return fd;
}

int bind_udp(const std::string& host, uint16_t port) { return bound_socket(SOCK_DGRAM, host, port); }

uint16_t local_port(int fd) {
    sockaddr_in a{};
    socklen_t len = sizeof a;
    getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
    return ntohs(a.sin_port);
}

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

}  // namespace skynet
