#include "config_parser.h"
#include <fstream>
#include <sstream>
#include <iostream>

using namespace std;


Config parse_config(const string& filename) {
    Config config;
    config.speaker.local_as = 65001;
    config.speaker.router_id = "10.0.0.1";
    config.speaker.hold_time = 90;

    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "WARNING: Could not open config file: " << filename << endl;
        cerr << "Using defaults (AS 65001, router-id 10.0.0.1, hold-time 90)" << endl;
        return config;
    }

    string line;
    int line_num = 0;

    while (getline(file, line)) {
        line_num++;

        // Trim whitespace
        size_t start = line.find_first_not_of(" \t");
        if (start == string::npos) continue;
        line = line.substr(start);

        // Skip comments and empty lines
        if (line.empty() || line[0] == '#') continue;

        istringstream iss(line);
        string keyword;
        iss >> keyword;

        if (keyword == "local_as") {
            iss >> config.speaker.local_as;
        } else if (keyword == "router_id") {
            iss >> config.speaker.router_id;
        } else if (keyword == "hold_time") {
            iss >> config.speaker.hold_time;
        } else if (keyword == "peer") {
            PeerConfig peer;
            iss >> peer.peer_ip >> peer.peer_port >> peer.peer_as;
            config.peers.push_back(peer);
        } else {
            cerr << "WARNING: Unknown config directive '" << keyword
                 << "' at line " << line_num << endl;
        }
    }

    return config;
}
