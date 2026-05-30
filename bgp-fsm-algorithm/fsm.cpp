#include "fsm.h"
#include <iostream>
#include <cstring>
#include <sstream>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

using namespace std;


BGPFiniteStateMachine::BGPFiniteStateMachine(const FSMConfig& config)
    : config(config),
      current_state(FSMState::Idle),
      socket_fd(-1),
      negotiated_hold_time(0),
      running(true) {
}

BGPFiniteStateMachine::~BGPFiniteStateMachine() {
    tcp_close();
}

void BGPFiniteStateMachine::shutdown() {
    if (!running) {
        return;
    }
    running = false;
    if (current_state == FSMState::Established && socket_fd >= 0) {
        cout << "\n[" << get_timestamp() << "] Initiating graceful shutdown" << endl;
        send_notification(ERR_CEASE, 0);
        transition_to(FSMState::Idle, "Administrative shutdown");
    }
    tcp_close();
}


// Utility functions
string BGPFiniteStateMachine::get_timestamp() {
    auto now = chrono::system_clock::now();
    time_t time = chrono::system_clock::to_time_t(now);
    struct tm local_time;
    localtime_r(&time, &local_time);

    char buffer[16];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &local_time);
    return string(buffer);
}

string BGPFiniteStateMachine::state_to_string(FSMState state) {
    switch (state) {
        case FSMState::Idle:        return "Idle";
        case FSMState::Connect:     return "Connect";
        case FSMState::Active:      return "Active";
        case FSMState::OpenSent:    return "OpenSent";
        case FSMState::OpenConfirm: return "OpenConfirm";
        case FSMState::Established: return "Established";
    }
    return "Unknown";
}

void BGPFiniteStateMachine::transition_to(FSMState new_state, const string& reason) {
    string old_state_str = state_to_string(current_state);
    string new_state_str = state_to_string(new_state);
    current_state = new_state;
    cout << "[" << get_timestamp() << "] FSM State: "
         << old_state_str << " -> " << new_state_str
         << " (" << reason << ")" << endl;
}

uint32_t BGPFiniteStateMachine::ip_to_uint32(const string& ip) {
    uint32_t result = 0;
    istringstream stream(ip);
    string octet;
    int shift = 24;

    while (getline(stream, octet, '.')) {
        result |= (stoi(octet) << shift);
        shift -= 8;
    }

    return result;
}

string BGPFiniteStateMachine::uint32_to_ip(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "."
         + to_string((ip >> 16) & 0xFF) + "."
         + to_string((ip >> 8) & 0xFF) + "."
         + to_string(ip & 0xFF);
}



// TCP operations
bool BGPFiniteStateMachine::tcp_connect() {
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        cout << "[" << get_timestamp() << "] TCP: Failed to create socket\n";
        return false;
    }

    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(config.peer_port);
    inet_pton(AF_INET, config.peer_ip.c_str(), &peer_addr.sin_addr);

    cout << "[" << get_timestamp() << "] TCP: Connecting to "
         << config.peer_ip << ":" << config.peer_port << "...\n";

    int result = connect(socket_fd, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    if (result < 0) {
        cout << "[" << get_timestamp() << "] TCP: Connection failed ("
             << strerror(errno) << ")" << endl;
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    cout << "[" << get_timestamp() << "] TCP: Connected\n";
    return true;
}

void BGPFiniteStateMachine::tcp_close() {
    if (socket_fd >= 0) {
        close(socket_fd);
        socket_fd = -1;
    }
}

bool BGPFiniteStateMachine::send_bytes(const uint8_t* data, int length) {
    int total_sent = 0;
    while (total_sent < length) {
        int sent = send(socket_fd, data + total_sent, length - total_sent, 0);
        if (sent <= 0) {
            cout << "[" << get_timestamp() << "] TCP: Send failed ("
                 << strerror(errno) << ")" << endl;
            return false;
        }
        total_sent += sent;
    }
    return true;
}

bool BGPFiniteStateMachine::read_bytes(uint8_t* buffer, int length) {
    int total_read = 0;
    while (total_read < length) {
        int received = recv(socket_fd, buffer + total_read, length - total_read, 0);
        if (received <= 0) {
            if (received == 0) {
                cout << "[" << get_timestamp() << "] TCP: Connection closed by peer\n";
            } else {
                cout << "[" << get_timestamp() << "] TCP: Read failed ("
                     << strerror(errno) << ")" << endl;
            }
            return false;
        }
        total_read += received;
    }
    return true;
}

// Message sending (wire format encoding)

// BGP OPEN message (RFC 4271 Section 4.2)
// Format:
//   Header (19 bytes): 16-byte marker + 2-byte length + 1-byte type
//   Payload: version (1) + AS (2) + hold time (2) + BGP ID (4) + opt params length (1) + optional parameters (variable)
//
// Optional parameters include capabilities (RFC 5492):
//   - Multiprotocol Extensions (capability 1): IPv4 unicast support
//   - 4-Byte ASN (capability 65): support for 32-bit AS numbers
// Modern BGP implementations require these capabilities to establish a session.
void BGPFiniteStateMachine::send_open() {
    uint8_t message[64];
    int offset = 0;

    // -- Header --

    // Marker: 16 bytes of 0xFF
    memset(message, 0xFF, BGP_MARKER_LENGTH);
    offset += BGP_MARKER_LENGTH;

    // Length placeholder — we'll fill it in after building the full message
    int length_offset = offset;
    offset += 2;

    // Type: OPEN
    message[offset++] = BGP_MSG_OPEN;

    // -- OPEN fixed fields --

    // Version: 4
    message[offset++] = BGP_VERSION;

    // My AS: 2 bytes (for 4-byte ASN, this is set to AS_TRANS=23456
    // and the real AS goes in the 4-byte ASN capability)
    uint16_t my_as = (uint16_t)config.local_as;
    message[offset++] = (my_as >> 8) & 0xFF;
    message[offset++] = my_as & 0xFF;

    // Hold Time: 2 bytes
    message[offset++] = (config.hold_time >> 8) & 0xFF;
    message[offset++] = config.hold_time & 0xFF;

    // BGP Identifier: 4 bytes (router ID as IP)
    uint32_t bgp_id = ip_to_uint32(config.router_id);
    message[offset++] = (bgp_id >> 24) & 0xFF;
    message[offset++] = (bgp_id >> 16) & 0xFF;
    message[offset++] = (bgp_id >> 8) & 0xFF;
    message[offset++] = bgp_id & 0xFF;

    // -- Optional Parameters --
    // Each optional parameter: type (1 byte) + length (1 byte) + value
    // Capability parameter type = 2
    // Each capability: code (1 byte) + length (1 byte) + value

    int opt_params_length_offset = offset;
    offset++;  // placeholder for opt params length

    int opt_params_start = offset;

    // Capability 1: Multiprotocol Extensions for IPv4 Unicast (RFC 4760)
    // Tells the peer we support IPv4 unicast routing
    message[offset++] = 2;    // opt param type: Capability
    message[offset++] = 6;    // opt param length: 6 bytes
    message[offset++] = 1;    // capability code: Multiprotocol Extensions
    message[offset++] = 4;    // capability length: 4 bytes
    message[offset++] = 0;    // AFI high byte
    message[offset++] = 1;    // AFI low byte: 1 = IPv4
    message[offset++] = 0;    // reserved
    message[offset++] = 1;    // SAFI: 1 = Unicast

    // Capability 2: 4-Byte AS Number (RFC 6793)
    // Tells the peer our real 4-byte AS number
    message[offset++] = 2;    // opt param type: Capability
    message[offset++] = 6;    // opt param length: 6 bytes
    message[offset++] = 65;   // capability code: 4-Byte ASN
    message[offset++] = 4;    // capability length: 4 bytes
    message[offset++] = (config.local_as >> 24) & 0xFF;
    message[offset++] = (config.local_as >> 16) & 0xFF;
    message[offset++] = (config.local_as >> 8) & 0xFF;
    message[offset++] = config.local_as & 0xFF;

    // Fill in the optional parameters length
    int opt_params_length = offset - opt_params_start;
    message[opt_params_length_offset] = opt_params_length;

    // Fill in the total message length in the header
    uint16_t total_length = offset;
    message[length_offset] = (total_length >> 8) & 0xFF;
    message[length_offset + 1] = total_length & 0xFF;

    send_bytes(message, offset);

    cout << "[" << get_timestamp() << "] SEND: OPEN (version="
         << (int)BGP_VERSION
         << ", AS=" << config.local_as
         << ", hold_time=" << config.hold_time
         << ", router_id=" << config.router_id
         << ", capabilities=[IPv4-Unicast, 4-Byte-ASN])" << endl;
}

// BGP KEEPALIVE message (RFC 4271 Section 4.4)
// Just a 19-byte header with no payload. Type = 4.
void BGPFiniteStateMachine::send_keepalive() {
    uint8_t message[19];
    int offset = 0;

    // Marker
    memset(message, 0xFF, BGP_MARKER_LENGTH);
    offset += BGP_MARKER_LENGTH;

    // Length: 19 (header only)
    uint16_t length = BGP_HEADER_LENGTH;
    message[offset++] = (length >> 8) & 0xFF;
    message[offset++] = length & 0xFF;

    // Type: KEEPALIVE
    message[offset++] = BGP_MSG_KEEPALIVE;

    send_bytes(message, offset);

    cout << "[" << get_timestamp() << "] SEND: KEEPALIVE\n";
}

// BGP NOTIFICATION message (RFC 4271 Section 4.5)
// Signals an error condition. Session is closed after sending.
void BGPFiniteStateMachine::send_notification(uint8_t error_code, uint8_t error_subcode) {
    uint8_t message[21];  // 19 header + 2 payload
    int offset = 0;

    // Marker
    memset(message, 0xFF, BGP_MARKER_LENGTH);
    offset += BGP_MARKER_LENGTH;

    // Length: 21
    uint16_t length = 21;
    message[offset++] = (length >> 8) & 0xFF;
    message[offset++] = length & 0xFF;

    // Type: NOTIFICATION
    message[offset++] = BGP_MSG_NOTIFICATION;

    // Error code and subcode
    message[offset++] = error_code;
    message[offset++] = error_subcode;

    send_bytes(message, offset);

    cout << "[" << get_timestamp() << "] SEND: NOTIFICATION (error="
         << (int)error_code << ", subcode=" << (int)error_subcode << ")" << endl;
}

// Message receiving (wire format parsing)
bool BGPFiniteStateMachine::read_header(BGPHeader& header) {
    uint8_t buffer[BGP_HEADER_LENGTH];

    if (!read_bytes(buffer, BGP_HEADER_LENGTH)) {
        return false;
    }

    // Validate marker (all 0xFF)
    for (int i = 0; i < BGP_MARKER_LENGTH; i++) {
        if (buffer[i] != 0xFF) {
            cout << "[" << get_timestamp() << "] ERROR: Invalid BGP marker\n";
            return false;
        }
    }

    // Parse length (big-endian)
    header.length = (buffer[16] << 8) | buffer[17];

    // Parse type
    header.type = buffer[18];

    return true;
}

bool BGPFiniteStateMachine::read_open_message(uint16_t payload_length, BGPOpenMessage& open_msg) {
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];

    if (!read_bytes(buffer, payload_length)) {
        return false;
    }

    open_msg.version = buffer[0];
    open_msg.my_as = (buffer[1] << 8) | buffer[2];
    open_msg.hold_time = (buffer[3] << 8) | buffer[4];
    open_msg.bgp_identifier = (buffer[5] << 24) | (buffer[6] << 16)
                             | (buffer[7] << 8) | buffer[8];
    open_msg.opt_params_len = buffer[9];

    if (open_msg.opt_params_len > 0) {
        parse_capabilities(buffer + 10, open_msg.opt_params_len);
    }

    return true;
}

// Parse and display capabilities from the OPEN message's optional parameters.
// Each optional parameter has: type (1 byte) + length (1 byte) + value.
// Capability parameters (type=2) contain: code (1 byte) + length (1 byte) + value.
void BGPFiniteStateMachine::parse_capabilities(const uint8_t* data, int length) {
    int pos = 0;
    while (pos < length) {
        uint8_t param_type = data[pos++];
        uint8_t param_length = data[pos++];

        if (param_type != 2) {
            pos += param_length;
            continue;
        }

        int param_end = pos + param_length;
        while (pos < param_end) {
            uint8_t cap_code = data[pos++];
            uint8_t cap_length = data[pos++];

            cout << "[" << get_timestamp() << "]   Capability: ";

            switch (cap_code) {
                case 1: {
                    uint16_t afi = (data[pos] << 8) | data[pos + 1];
                    uint8_t safi = data[pos + 3];
                    string afi_name = (afi == 1) ? "IPv4" : (afi == 2) ? "IPv6" : to_string(afi);
                    string safi_name = (safi == 1) ? "Unicast" : (safi == 2) ? "Multicast" : to_string(safi);
                    cout << "Multiprotocol Extensions (" << afi_name << " " << safi_name << ")" << endl;
                    break;
                }
                case 2:
                    cout << "Route Refresh" << endl;
                    break;
                case 64:
                    cout << "Graceful Restart" << endl;
                    break;
                case 65: {
                    uint32_t asn = (data[pos] << 24) | (data[pos + 1] << 16)
                                 | (data[pos + 2] << 8) | data[pos + 3];
                    cout << "4-Byte ASN (AS " << asn << ")" << endl;
                    break;
                }
                case 5:
                    cout << "Extended Next Hop Encoding" << endl;
                    break;
                case 6:
                    cout << "Extended Message" << endl;
                    break;
                case 69:
                    cout << "Add-Path" << endl;
                    break;
                case 70:
                    cout << "Enhanced Route Refresh" << endl;
                    break;
                case 73: {
                    string hostname = "";
                    if (cap_length > 0) {
                        uint8_t host_len = data[pos];
                        hostname = string((char*)&data[pos + 1], host_len);
                    }
                    cout << "FQDN (hostname: " << hostname << ")" << endl;
                    break;
                }
                default:
                    cout << "Unknown (code " << (int)cap_code << ")" << endl;
                    break;
            }

            pos += cap_length;
        }
    }
}

// FSM state handlers

// Connect state: initiate TCP connection and send OPEN
void BGPFiniteStateMachine::handle_connect() {
    if (!tcp_connect()) {
        transition_to(FSMState::Active, "TCP connection failed");

        cout << "[" << get_timestamp() << "] Waiting 5 seconds before retry...\n";
        for (int i = 0; i < 5 && running; i++) {
            sleep(1);
        }
        if (!running) return;

        transition_to(FSMState::Connect, "ConnectRetryTimer expired, retrying");
        handle_connect();
        return;
    }

    transition_to(FSMState::OpenSent, "TCP connection confirmed");
    send_open();
}

// OpenSent state: wait for peer's OPEN message
void BGPFiniteStateMachine::handle_open_sent() {
    BGPHeader header;
    if (!read_header(header)) {
        transition_to(FSMState::Idle, "Failed to read message header");
        tcp_close();
        return;
    }

    if (header.type == BGP_MSG_NOTIFICATION) {
        cout << "[" << get_timestamp() << "] RECV: NOTIFICATION\n";
        transition_to(FSMState::Idle, "Received NOTIFICATION from peer");
        tcp_close();
        return;
    }

    if (header.type != BGP_MSG_OPEN) {
        cout << "[" << get_timestamp() << "] ERROR: Expected OPEN, got type "
             << (int)header.type << endl;
        send_notification(ERR_FSM, 0);
        transition_to(FSMState::Idle, "Unexpected message type");
        tcp_close();
        return;
    }

    // Parse the OPEN message payload
    uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
    BGPOpenMessage peer_open;
    if (!read_open_message(payload_length, peer_open)) {
        transition_to(FSMState::Idle, "Failed to read OPEN payload");
        tcp_close();
        return;
    }

    string peer_router_id = uint32_to_ip(peer_open.bgp_identifier);
    cout << "[" << get_timestamp() << "] RECV: OPEN (version="
         << (int)peer_open.version
         << ", AS=" << peer_open.my_as
         << ", hold_time=" << peer_open.hold_time
         << ", router_id=" << peer_router_id << ")" << endl;

    // Validate BGP version
    if (peer_open.version != BGP_VERSION) {
        cout << "[" << get_timestamp() << "] ERROR: Unsupported BGP version "
             << (int)peer_open.version << endl;
        send_notification(ERR_OPEN_MESSAGE, 1);
        transition_to(FSMState::Idle, "Unsupported BGP version");
        tcp_close();
        return;
    }

    // Negotiate hold time: use the smaller of local and peer hold times
    // (RFC 4271 Section 4.2)
    negotiated_hold_time = config.hold_time;
    if (peer_open.hold_time < negotiated_hold_time) {
        negotiated_hold_time = peer_open.hold_time;
    }
    cout << "[" << get_timestamp() << "] Negotiated hold time: "
         << negotiated_hold_time << " seconds\n";

    transition_to(FSMState::OpenConfirm, "Valid OPEN received");
    send_keepalive();
}

// OpenConfirm state: wait for peer's KEEPALIVE
void BGPFiniteStateMachine::handle_open_confirm() {
    BGPHeader header;
    if (!read_header(header)) {
        transition_to(FSMState::Idle, "Failed to read message header");
        tcp_close();
        return;
    }

    if (header.type == BGP_MSG_NOTIFICATION) {
        cout << "[" << get_timestamp() << "] RECV: NOTIFICATION\n";
        transition_to(FSMState::Idle, "Received NOTIFICATION from peer");
        tcp_close();
        return;
    }

    if (header.type == BGP_MSG_KEEPALIVE) {
        cout << "[" << get_timestamp() << "] RECV: KEEPALIVE\n";
        transition_to(FSMState::Established, "KEEPALIVE received");
        return;
    }

    // GoBGP may send its OPEN before our KEEPALIVE arrives,
    // or send additional messages. Handle gracefully.
    if (header.type == BGP_MSG_OPEN) {
        // Skip any remaining payload
        uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
        uint8_t discard[BGP_MAX_MESSAGE_SIZE];
        read_bytes(discard, payload_length);

        // Try reading the next message (should be KEEPALIVE)
        handle_open_confirm();
        return;
    }

    cout << "[" << get_timestamp() << "] ERROR: Expected KEEPALIVE, got type "
         << (int)header.type << endl;
    send_notification(ERR_FSM, 0);
    transition_to(FSMState::Idle, "Unexpected message type");
    tcp_close();
}

// Established state: exchange KEEPALIVEs periodically
void BGPFiniteStateMachine::handle_established() {
    cout << "[" << get_timestamp() << "] === BGP Session Established ===\n";

    // Keepalive interval is hold_time / 3 (RFC 4271 Section 4.4)
    int keepalive_interval = negotiated_hold_time / 3;
    if (keepalive_interval < 1) {
        keepalive_interval = 1;
    }

    cout << "[" << get_timestamp() << "] Keepalive interval: "
         << keepalive_interval << " seconds\n";

    // Main keepalive loop.
    // Use poll() to check for incoming messages while also sending
    // keepalives on our own schedule.
    while (current_state == FSMState::Established && running) {
        struct pollfd pfd;
        pfd.fd = socket_fd;
        pfd.events = POLLIN;

        // Wait up to keepalive_interval seconds for incoming data
        int poll_result = poll(&pfd, 1, keepalive_interval * 1000);

        if (poll_result < 0) {
            if (!running) {
                return;
            }
            cout << "[" << get_timestamp() << "] ERROR: poll() failed ("
                 << strerror(errno) << ")" << endl;
            transition_to(FSMState::Idle, "Socket error");
            tcp_close();
            return;
        }

        if (poll_result > 0 && (pfd.revents & POLLIN)) {
            // Data available — read the message
            BGPHeader header;
            if (!read_header(header)) {
                transition_to(FSMState::Idle, "Connection lost");
                tcp_close();
                return;
            }

            if (header.type == BGP_MSG_KEEPALIVE) {
                cout << "[" << get_timestamp() << "] RECV: KEEPALIVE\n";
            } else if (header.type == BGP_MSG_NOTIFICATION) {
                // Read the notification payload
                uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
                if (payload_length >= 2) {
                    uint8_t notif_data[2];
                    read_bytes(notif_data, 2);
                    cout << "[" << get_timestamp() << "] RECV: NOTIFICATION (error="
                         << (int)notif_data[0] << ", subcode="
                         << (int)notif_data[1] << ")" << endl;
                } else {
                    cout << "[" << get_timestamp() << "] RECV: NOTIFICATION\n";
                }
                transition_to(FSMState::Idle, "Received NOTIFICATION from peer");
                tcp_close();
                return;
            } else if (header.type == BGP_MSG_UPDATE) {
                // Skip UPDATE payload — we don't process routes in this module
                uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
                if (payload_length > 0) {
                    uint8_t discard[BGP_MAX_MESSAGE_SIZE];
                    read_bytes(discard, payload_length);
                }
                cout << "[" << get_timestamp() << "] RECV: UPDATE (ignored, "
                     << header.length << " bytes)\n";
            } else {
                cout << "[" << get_timestamp() << "] RECV: Unknown message type "
                     << (int)header.type << endl;
            }
        }

        // Send our keepalive
        if (current_state == FSMState::Established) {
            send_keepalive();
        }
    }
}

// Main FSM run loop with automatic reconnection.
// If the session drops (hold timer, peer crash, etc.), the FSM goes back
// to Idle and retries after a delay instead of exiting.
void BGPFiniteStateMachine::run() {
    cout << "[" << get_timestamp() << "] BGP Speaker starting" << endl;
    cout << "[" << get_timestamp() << "] Local AS: " << config.local_as
         << ", Router ID: " << config.router_id << endl;
    cout << "[" << get_timestamp() << "] Peer: " << config.peer_ip
         << ":" << config.peer_port << "\n" << endl;

    int connect_retry_seconds = 10;

    while (running) {
        current_state = FSMState::Idle;
        transition_to(FSMState::Connect, "ManualStart");

        handle_connect();

        if (current_state == FSMState::OpenSent) {
            handle_open_sent();
        }

        if (current_state == FSMState::OpenConfirm) {
            handle_open_confirm();
        }

        if (current_state == FSMState::Established) {
            handle_established();
        }

        // If we get here, the session dropped. Retry after a delay.
        if (running) {
            tcp_close();
            cout << "[" << get_timestamp() << "] Session ended. Retrying in "
                 << connect_retry_seconds << " seconds..." << endl;
            for (int i = 0; i < connect_retry_seconds && running; i++) {
                sleep(1);
            }
        }
    }

    cout << "\n[" << get_timestamp() << "] BGP Speaker stopped" << endl;
}
