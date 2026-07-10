#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "bgp_types.h"
#include <vector>
#include <string>

using namespace std;

struct Config {
    SpeakerConfig speaker;
    vector<PeerConfig> peers;
};

Config parse_config(const string& filename);

#endif
