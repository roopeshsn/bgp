#ifndef BGP_TYPES_H
#define BGP_TYPES_H

#include <string>
#include <cstdint>

using namespace std;


enum class RouteProtocol {
    CONNECTED,
    STATIC,
    OSPF,
    BGP
};

enum class RouteState {
    PENDING,
    INSTALLED,
    FAILED,
    WITHDRAWN
};

struct Prefix {
    string network;     // "10.1.0.0"
    uint8_t length;     // 24

    bool operator==(const Prefix& other) const {
        return network == other.network && length == other.length;
    }

    bool operator<(const Prefix& other) const {
        if (network != other.network) return network < other.network;
        return length < other.length;
    }

    string to_string() const {
        return network + "/" + std::to_string(length);
    }
};

struct Route {
    Prefix prefix;
    string next_hop;
    RouteProtocol protocol;
    uint8_t admin_distance;
    uint32_t metric;
    string source_info;
    RouteState state;
};

struct ProgramResult {
    bool success;
    string error;
};

#endif
