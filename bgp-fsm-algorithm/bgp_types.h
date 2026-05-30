#ifndef BGP_TYPES_H
#define BGP_TYPES_H

#include <string>
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

// BGP message type codes (RFC 4271 Section 4.1)
const uint8_t BGP_MSG_OPEN         = 1;
const uint8_t BGP_MSG_UPDATE       = 2;
const uint8_t BGP_MSG_NOTIFICATION = 3;
const uint8_t BGP_MSG_KEEPALIVE    = 4;

// BGP header constants
const int BGP_HEADER_LENGTH    = 19;   // 16 marker + 2 length + 1 type
const int BGP_MARKER_LENGTH    = 16;
const int BGP_MAX_MESSAGE_SIZE = 4096;

// BGP OPEN message constants
const uint8_t BGP_VERSION = 4;

// BGP NOTIFICATION error codes (RFC 4271 Section 4.5)
const uint8_t ERR_MESSAGE_HEADER = 1;
const uint8_t ERR_OPEN_MESSAGE   = 2;
const uint8_t ERR_UPDATE_MESSAGE = 3;
const uint8_t ERR_HOLD_TIMER     = 4;
const uint8_t ERR_FSM            = 5;
const uint8_t ERR_CEASE          = 6;

// BGP message header (RFC 4271 Section 4.1)
// Every BGP message starts with this 19-byte header.
struct BGPHeader {
    uint8_t marker[16];   // all 0xFF
    uint16_t length;      // total message length including header
    uint8_t type;         // 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE
};

// BGP OPEN message payload (RFC 4271 Section 4.2)
// Sent by each peer to establish the session parameters.
struct BGPOpenMessage {
    uint8_t version;           // BGP version, always 4
    uint16_t my_as;            // sender's AS number
    uint16_t hold_time;        // proposed hold time in seconds
    uint32_t bgp_identifier;   // router ID as 32-bit integer
    uint8_t opt_params_len;    // length of optional parameters (0 for now)
};

// BGP NOTIFICATION message payload (RFC 4271 Section 4.5)
// Sent when an error is detected, causes session teardown.
struct BGPNotificationMessage {
    uint8_t error_code;
    uint8_t error_subcode;
};

// Configuration for our BGP speaker
struct FSMConfig {
    uint32_t local_as;
    string router_id;       // e.g., "10.0.0.1"
    uint16_t hold_time;     // proposed hold time in seconds (default 90)
    string peer_ip;         // peer's IP address
    uint16_t peer_port;     // peer's BGP port (e.g., 1790)
};

#endif
