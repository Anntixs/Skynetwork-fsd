#pragma once
#include <cstdint>
#include <string>

namespace skynet {

int listen_tcp(const std::string& host, uint16_t port);   // non-blocking listening socket
int bind_udp(const std::string& host, uint16_t port);     // non-blocking UDP socket
uint16_t local_port(int fd);
void set_nonblocking(int fd);
int64_t now_ms();

}  // namespace skynet
