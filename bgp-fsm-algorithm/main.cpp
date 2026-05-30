#include <iostream>
#include <csignal>
#include "bgp_types.h"
#include "fsm.h"

using namespace std;

// Global pointer for signal handler to trigger graceful shutdown
BGPFiniteStateMachine* global_fsm = nullptr;

void signal_handler(int signal) {
    if (global_fsm != nullptr) {
        global_fsm->shutdown();
    }
}

int main(int argc, char* argv[]) {
    // Default configuration
    FSMConfig config;
    config.local_as  = 65001;
    config.router_id = "10.0.0.1";
    config.hold_time = 90;
    config.peer_ip   = "127.0.0.1";
    config.peer_port = 1790;

    // Allow overriding via command-line arguments
    // Usage: ./bgp_fsm [peer_ip] [peer_port] [local_as] [router_id] [hold_time]
    if (argc >= 2) config.peer_ip   = argv[1];
    if (argc >= 3) config.peer_port = stoi(argv[2]);
    if (argc >= 4) config.local_as  = stoi(argv[3]);
    if (argc >= 5) config.router_id = argv[4];
    if (argc >= 6) config.hold_time = stoi(argv[5]);

    // Disable stdout buffering so output appears immediately,
    // even when redirected to a file.
    setbuf(stdout, NULL);

    // Handle Ctrl+C gracefully
    signal(SIGINT, signal_handler);

    BGPFiniteStateMachine fsm(config);
    global_fsm = &fsm;

    fsm.run();

    return 0;
}
