// BGP Speaker — Multi-Peer
//
// Connects to multiple BGP peers, each in its own thread.
// Receives and advertises routes via UPDATE messages, runs best path
// selection across all peers, and programs winners into the kernel.
//
// Pipeline: TCP → PeerSession (per thread) → BGPSpeaker (shared RIB) → Kernel
//
// Build:
//   g++ -std=c++17 -pthread -o bgp_speaker main.cpp peer_session.cpp speaker.cpp update_parser.cpp update_encoder.cpp config_parser.cpp rib.cpp route_programmer.cpp
//
// Run:
//   ./bgp_speaker                   (uses bgp.conf)
//   ./bgp_speaker myconfig.conf     (custom config file)
//   sudo ./bgp_speaker              (programs kernel routes)

#include <csignal>
#include "bgp_types.h"
#include "config_parser.h"
#include "speaker.h"

using namespace std;

BGPSpeaker* global_speaker = nullptr;

void signal_handler(int signal) {
    if (global_speaker != nullptr) {
        global_speaker->request_shutdown();
    }
}

int main(int argc, char* argv[]) {
    string config_file = "bgp.conf";
    if (argc >= 2) config_file = argv[1];

    Config config = parse_config(config_file);

    setbuf(stdout, NULL);
    signal(SIGINT, signal_handler);

    BGPSpeaker speaker(config.speaker, config.peers);
    global_speaker = &speaker;
    speaker.run();

    return 0;
}
