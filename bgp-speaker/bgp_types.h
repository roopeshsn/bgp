#ifndef BGP_TYPES_H
#define BGP_TYPES_H

#include <string>
#include <vector>
#include <cstdint>

using namespace std;


// BGP FSM states (RFC 4271 Section 8.2.2)
enum class FSMState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established
};

enum class Origin {
    IGP,
    EGP,
    INCOMPLETE
};

enum class PeerType {
    EBGP,
    IBGP
};

enum class RouteState {
    PENDING,
    INSTALLED,
    FAILED,
    WITHDRAWN
};

// BGP message type codes (RFC 4271 Section 4.1)
const uint8_t BGP_MSG_OPEN         = 1;
const uint8_t BGP_MSG_UPDATE       = 2;
const uint8_t BGP_MSG_NOTIFICATION = 3;
const uint8_t BGP_MSG_KEEPALIVE    = 4;

const int BGP_HEADER_LENGTH    = 19;
const int BGP_MARKER_LENGTH    = 16;
const int BGP_MAX_MESSAGE_SIZE = 4096;
const uint8_t BGP_VERSION      = 4;

// NOTIFICATION error codes (RFC 4271 Section 4.5)
const uint8_t ERR_MESSAGE_HEADER = 1;
const uint8_t ERR_OPEN_MESSAGE   = 2;
const uint8_t ERR_UPDATE_MESSAGE = 3;
const uint8_t ERR_HOLD_TIMER     = 4;
const uint8_t ERR_FSM            = 5;
const uint8_t ERR_CEASE          = 6;


struct BGPHeader {
    uint8_t marker[16];
    uint16_t length;
    uint8_t type;
};

struct BGPOpenMessage {
    uint8_t version;
    uint16_t my_as;
    uint16_t hold_time;
    uint32_t bgp_identifier;
    uint8_t opt_params_len;
};

struct BGPNotificationMessage {
    uint8_t error_code;
    uint8_t error_subcode;
};

struct FSMConfig {
    uint32_t local_as;
    string router_id;
    uint16_t hold_time;
    string peer_ip;
    uint16_t peer_port;
    uint32_t peer_as;
};

struct SpeakerConfig {
    uint32_t local_as;
    string router_id;
    uint16_t hold_time;
};

struct PeerConfig {
    string peer_ip;
    uint16_t peer_port;
    uint32_t peer_as;
};


struct Prefix {
    string network;
    uint8_t length;

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

struct PathAttributes {
    Origin origin;
    vector<uint32_t> as_path;
    string next_hop;
    uint32_t local_pref;
    uint32_t med;
    vector<uint32_t> communities;
    bool atomic_aggregate;
    uint32_t aggregator_as;
    string aggregator_ip;
};

struct RIBEntry {
    Prefix prefix;
    PathAttributes attributes;
    uint32_t weight;
    PeerType peer_type;
    uint32_t neighbor_as;
    bool locally_originated;
    string peer_ip;
    bool is_best;
    int decisive_step;
    string decisive_reason;
};

// UPDATE message parse result
struct ParsedUpdate {
    vector<Prefix> withdrawn_routes;
    PathAttributes attributes;
    vector<Prefix> nlri;
    bool has_attributes;
};

// For kernel route programming
struct KernelRoute {
    Prefix prefix;
    string next_hop;
    RouteState state;
};

struct ProgramResult {
    bool success;
    string error;
};

#endif
