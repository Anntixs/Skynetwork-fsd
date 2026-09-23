// skynet-fsd: SkyNetwork Flight Simulator Daemon.
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "fsd_server.h"

int main(int argc, char** argv) {
    skynet::FsdConfig cfg;
    std::string db = "skynetwork.db";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", a.c_str());
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--db") db = next();
        else if (a == "--host") cfg.host = next();
        else if (a == "--port") cfg.port = static_cast<uint16_t>(std::atoi(next().c_str()));
        else if (a == "--http-port") cfg.http_port = static_cast<uint16_t>(std::atoi(next().c_str()));
        else if (a == "--name") cfg.server_name = next();
        else if (a == "--motd") cfg.motd = {next()};
        else {
            std::fprintf(stderr,
                         "usage: skynet-fsd [--db FILE] [--host ADDR] [--port 6809] [--http-port 8080]\n"
                         "                  [--name NAME] [--motd TEXT]\n");
            return 2;
        }
    }
    std::signal(SIGPIPE, SIG_IGN);
    try {
        skynet::Accounts accounts(db);
        skynet::FsdServer server(accounts, cfg);
        server.bind();
        std::fprintf(stderr, "SkyNetwork FSD %s listening on %s:%u, data feed on :%u\n", cfg.server_name.c_str(),
                     cfg.host.c_str(), server.port(), server.http_port());
        std::fflush(stderr);
        server.run();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "fatal: %s\n", e.what());
        return 1;
    }
}
