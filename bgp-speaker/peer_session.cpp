#include "peer_session.h"
#include "speaker.h"
#include "update_parser.h"
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


PeerSession::PeerSession(BGPSpeaker& speaker, const PeerConfig& peer, int peer_index)
    : speaker(speaker),
      peer(peer),
      peer_index(peer_index),
      current_state(FSMState::Idle),
      socket_fd(-1),
      negotiated_hold_time(0),
      peer_supports_4byte_asn(false),
      removed(false) {
}

FSMState PeerSession::get_state() const { return current_state; }
const PeerConfig& PeerSession::get_peer_config() const { return peer; }

bool PeerSession::send_update(const vector<uint8_t>& message) {
    if (current_state != FSMState::Established || socket_fd < 0) return false;
    return send_bytes(message.data(), message.size());
}

void PeerSession::request_stop() {
    removed.store(true, memory_order_relaxed);
    if (socket_fd >= 0) {
        shutdown(socket_fd, SHUT_RDWR);
    }
}

bool PeerSession::is_active() const {
    return !removed.load(memory_order_relaxed) && speaker.is_running();
}


// Utility functions

string PeerSession::get_timestamp() {
    auto now = chrono::system_clock::now();
    time_t time = chrono::system_clock::to_time_t(now);
    struct tm local_time;
    localtime_r(&time, &local_time);

    char buffer[16];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &local_time);
    return string(buffer);
}

string PeerSession::log_prefix() {
    return "[" + get_timestamp() + "] [" + peer.peer_ip + "] ";
}

string PeerSession::state_to_string(FSMState state) {
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

void PeerSession::transition_to(FSMState new_state, const string& reason) {
    string old_state_str = state_to_string(current_state);
    string new_state_str = state_to_string(new_state);
    current_state = new_state;
    cout << log_prefix() << "FSM: "
         << old_state_str << " -> " << new_state_str
         << " (" << reason << ")" << endl;
}

uint32_t PeerSession::ip_to_uint32(const string& ip) {
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

string PeerSession::uint32_to_ip(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "."
         + to_string((ip >> 16) & 0xFF) + "."
         + to_string((ip >> 8) & 0xFF) + "."
         + to_string(ip & 0xFF);
}

string PeerSession::as_path_to_string(const vector<uint32_t>& as_path) {
    string result;
    for (size_t i = 0; i < as_path.size(); i++) {
        if (i > 0) result += " ";
        result += to_string(as_path[i]);
    }
    return result;
}


// TCP operations

bool PeerSession::tcp_connect() {
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        cout << log_prefix() << "TCP: Failed to create socket" << endl;
        return false;
    }

    struct sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(peer.peer_port);
    inet_pton(AF_INET, peer.peer_ip.c_str(), &peer_addr.sin_addr);

    cout << log_prefix() << "TCP: Connecting to "
         << peer.peer_ip << ":" << peer.peer_port << "..." << endl;

    int result = connect(socket_fd, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    if (result < 0) {
        cout << log_prefix() << "TCP: Connection failed ("
             << strerror(errno) << ")" << endl;
        close(socket_fd);
        socket_fd = -1;
        return false;
    }

    cout << log_prefix() << "TCP: Connected" << endl;
    return true;
}

void PeerSession::tcp_close() {
    if (socket_fd >= 0) {
        close(socket_fd);
        socket_fd = -1;
    }
}

bool PeerSession::send_bytes(const uint8_t* data, int length) {
    int total_sent = 0;
    while (total_sent < length) {
        int sent = send(socket_fd, data + total_sent, length - total_sent, 0);
        if (sent <= 0) {
            cout << log_prefix() << "TCP: Send failed ("
                 << strerror(errno) << ")" << endl;
            return false;
        }
        total_sent += sent;
    }
    return true;
}

bool PeerSession::read_bytes(uint8_t* buffer, int length) {
    int total_read = 0;
    while (total_read < length) {
        int received = recv(socket_fd, buffer + total_read, length - total_read, 0);
        if (received <= 0) {
            if (received == 0) {
                cout << log_prefix() << "TCP: Connection closed by peer" << endl;
            } else {
                cout << log_prefix() << "TCP: Read failed ("
                     << strerror(errno) << ")" << endl;
            }
            return false;
        }
        total_read += received;
    }
    return true;
}


// Message sending

void PeerSession::send_open() {
    const SpeakerConfig& cfg = speaker.get_config();

    uint8_t message[64];
    int offset = 0;

    memset(message, 0xFF, BGP_MARKER_LENGTH);
    offset += BGP_MARKER_LENGTH;

    int length_offset = offset;
    offset += 2;

    message[offset++] = BGP_MSG_OPEN;
    message[offset++] = BGP_VERSION;

    uint16_t my_as = (uint16_t)cfg.local_as;
    message[offset++] = (my_as >> 8) & 0xFF;
    message[offset++] = my_as & 0xFF;

    message[offset++] = (cfg.hold_time >> 8) & 0xFF;
    message[offset++] = cfg.hold_time & 0xFF;

    uint32_t bgp_id = ip_to_uint32(cfg.router_id);
    message[offset++] = (bgp_id >> 24) & 0xFF;
    message[offset++] = (bgp_id >> 16) & 0xFF;
    message[offset++] = (bgp_id >> 8) & 0xFF;
    message[offset++] = bgp_id & 0xFF;

    int opt_params_length_offset = offset;
    offset++;
    int opt_params_start = offset;

    // Multiprotocol Extensions — IPv4 Unicast
    message[offset++] = 2;
    message[offset++] = 6;
    message[offset++] = 1;
    message[offset++] = 4;
    message[offset++] = 0;
    message[offset++] = 1;
    message[offset++] = 0;
    message[offset++] = 1;

    // 4-Byte ASN
    message[offset++] = 2;
    message[offset++] = 6;
    message[offset++] = 65;
    message[offset++] = 4;
    message[offset++] = (cfg.local_as >> 24) & 0xFF;
    message[offset++] = (cfg.local_as >> 16) & 0xFF;
    message[offset++] = (cfg.local_as >> 8) & 0xFF;
    message[offset++] = cfg.local_as & 0xFF;

    int opt_params_length = offset - opt_params_start;
    message[opt_params_length_offset] = opt_params_length;

    uint16_t total_length = offset;
    message[length_offset] = (total_length >> 8) & 0xFF;
    message[length_offset + 1] = total_length & 0xFF;

    send_bytes(message, offset);

    cout << log_prefix() << "SEND: OPEN (AS=" << cfg.local_as
         << ", hold_time=" << cfg.hold_time
         << ", router_id=" << cfg.router_id << ")" << endl;
}

void PeerSession::send_keepalive() {
    uint8_t message[19];
    int offset = 0;

    memset(message, 0xFF, BGP_MARKER_LENGTH);
    offset += BGP_MARKER_LENGTH;

    uint16_t length = BGP_HEADER_LENGTH;
    message[offset++] = (length >> 8) & 0xFF;
    message[offset++] = length & 0xFF;

    message[offset++] = BGP_MSG_KEEPALIVE;

    send_bytes(message, offset);
    cout << log_prefix() << "SEND: KEEPALIVE" << endl;
}

void PeerSession::send_notification(uint8_t error_code, uint8_t error_subcode) {
    uint8_t message[21];
    int offset = 0;

    memset(message, 0xFF, BGP_MARKER_LENGTH);
    offset += BGP_MARKER_LENGTH;

    uint16_t length = 21;
    message[offset++] = (length >> 8) & 0xFF;
    message[offset++] = length & 0xFF;

    message[offset++] = BGP_MSG_NOTIFICATION;
    message[offset++] = error_code;
    message[offset++] = error_subcode;

    send_bytes(message, offset);
    cout << log_prefix() << "SEND: NOTIFICATION (error="
         << (int)error_code << ", subcode=" << (int)error_subcode << ")" << endl;
}


// Message receiving

bool PeerSession::read_header(BGPHeader& header) {
    uint8_t buffer[BGP_HEADER_LENGTH];

    if (!read_bytes(buffer, BGP_HEADER_LENGTH)) return false;

    for (int i = 0; i < BGP_MARKER_LENGTH; i++) {
        if (buffer[i] != 0xFF) {
            cout << log_prefix() << "ERROR: Invalid BGP marker" << endl;
            return false;
        }
    }

    header.length = (buffer[16] << 8) | buffer[17];
    header.type = buffer[18];
    return true;
}

bool PeerSession::read_open_message(uint16_t payload_length, BGPOpenMessage& open_msg) {
    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];

    if (!read_bytes(buffer, payload_length)) return false;

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

void PeerSession::parse_capabilities(const uint8_t* data, int length) {
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

            cout << log_prefix() << "  Capability: ";

            switch (cap_code) {
                case 1: {
                    uint16_t afi = (data[pos] << 8) | data[pos + 1];
                    uint8_t safi = data[pos + 3];
                    string afi_name = (afi == 1) ? "IPv4" : (afi == 2) ? "IPv6" : to_string(afi);
                    string safi_name = (safi == 1) ? "Unicast" : (safi == 2) ? "Multicast" : to_string(safi);
                    cout << "Multiprotocol Extensions (" << afi_name << " " << safi_name << ")" << endl;
                    break;
                }
                case 2:  cout << "Route Refresh" << endl; break;
                case 64: cout << "Graceful Restart" << endl; break;
                case 65: {
                    uint32_t asn = (data[pos] << 24) | (data[pos + 1] << 16)
                                 | (data[pos + 2] << 8) | data[pos + 3];
                    cout << "4-Byte ASN (AS " << asn << ")" << endl;
                    peer_supports_4byte_asn = true;
                    break;
                }
                case 5:  cout << "Extended Next Hop Encoding" << endl; break;
                case 6:  cout << "Extended Message" << endl; break;
                case 69: cout << "Add-Path" << endl; break;
                case 70: cout << "Enhanced Route Refresh" << endl; break;
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


// UPDATE processing — parse then delegate to speaker

void PeerSession::process_update(const uint8_t* payload, uint16_t payload_length) {
    ParsedUpdate update;
    if (!parse_update(payload, payload_length, update)) {
        cout << log_prefix() << "ERROR: Failed to parse UPDATE" << endl;
        return;
    }

    if (update.withdrawn_routes.empty() && update.nlri.empty()) {
        cout << log_prefix() << "RECV: End-of-RIB marker" << endl;
        return;
    }

    for (auto& prefix : update.withdrawn_routes) {
        cout << log_prefix() << "WITHDRAW: " << prefix.to_string() << endl;
    }

    for (auto& prefix : update.nlri) {
        cout << log_prefix() << "NLRI: " << prefix.to_string()
             << " via " << update.attributes.next_hop
             << " AS_PATH [" << as_path_to_string(update.attributes.as_path) << "]" << endl;
    }

    speaker.apply_update(peer_index, update);
}


// FSM state handlers

void PeerSession::handle_connect() {
    if (!tcp_connect()) {
        transition_to(FSMState::Active, "TCP connection failed");

        cout << log_prefix() << "Waiting 5 seconds before retry..." << endl;
        for (int i = 0; i < 5 && is_active(); i++) {
            sleep(1);
        }
        if (!is_active()) return;

        transition_to(FSMState::Connect, "ConnectRetryTimer expired, retrying");
        handle_connect();
        return;
    }

    transition_to(FSMState::OpenSent, "TCP connection confirmed");
    send_open();
}

void PeerSession::handle_open_sent() {
    BGPHeader header;
    if (!read_header(header)) {
        transition_to(FSMState::Idle, "Failed to read message header");
        tcp_close();
        return;
    }

    if (header.type == BGP_MSG_NOTIFICATION) {
        cout << log_prefix() << "RECV: NOTIFICATION" << endl;
        transition_to(FSMState::Idle, "Received NOTIFICATION from peer");
        tcp_close();
        return;
    }

    if (header.type != BGP_MSG_OPEN) {
        cout << log_prefix() << "ERROR: Expected OPEN, got type "
             << (int)header.type << endl;
        send_notification(ERR_FSM, 0);
        transition_to(FSMState::Idle, "Unexpected message type");
        tcp_close();
        return;
    }

    uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
    BGPOpenMessage peer_open;
    if (!read_open_message(payload_length, peer_open)) {
        transition_to(FSMState::Idle, "Failed to read OPEN payload");
        tcp_close();
        return;
    }

    string peer_router_id = uint32_to_ip(peer_open.bgp_identifier);
    cout << log_prefix() << "RECV: OPEN (version=" << (int)peer_open.version
         << ", AS=" << peer_open.my_as
         << ", hold_time=" << peer_open.hold_time
         << ", router_id=" << peer_router_id << ")" << endl;

    if (peer_open.version != BGP_VERSION) {
        send_notification(ERR_OPEN_MESSAGE, 1);
        transition_to(FSMState::Idle, "Unsupported BGP version");
        tcp_close();
        return;
    }

    const SpeakerConfig& cfg = speaker.get_config();
    negotiated_hold_time = cfg.hold_time;
    if (peer_open.hold_time < negotiated_hold_time) {
        negotiated_hold_time = peer_open.hold_time;
    }
    cout << log_prefix() << "Negotiated hold time: "
         << negotiated_hold_time << " seconds" << endl;

    transition_to(FSMState::OpenConfirm, "Valid OPEN received");
    send_keepalive();
}

void PeerSession::handle_open_confirm() {
    BGPHeader header;
    if (!read_header(header)) {
        transition_to(FSMState::Idle, "Failed to read message header");
        tcp_close();
        return;
    }

    if (header.type == BGP_MSG_NOTIFICATION) {
        cout << log_prefix() << "RECV: NOTIFICATION" << endl;
        transition_to(FSMState::Idle, "Received NOTIFICATION from peer");
        tcp_close();
        return;
    }

    if (header.type == BGP_MSG_KEEPALIVE) {
        cout << log_prefix() << "RECV: KEEPALIVE" << endl;
        transition_to(FSMState::Established, "KEEPALIVE received");
        return;
    }

    if (header.type == BGP_MSG_OPEN) {
        uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
        uint8_t discard[BGP_MAX_MESSAGE_SIZE];
        read_bytes(discard, payload_length);
        handle_open_confirm();
        return;
    }

    cout << log_prefix() << "ERROR: Expected KEEPALIVE, got type "
         << (int)header.type << endl;
    send_notification(ERR_FSM, 0);
    transition_to(FSMState::Idle, "Unexpected message type");
    tcp_close();
}

void PeerSession::handle_established() {
    cout << log_prefix() << "=== BGP Session Established ===" << endl;

    int keepalive_interval = negotiated_hold_time / 3;
    if (keepalive_interval < 1) keepalive_interval = 1;

    cout << log_prefix() << "Keepalive interval: "
         << keepalive_interval << " seconds" << endl;

    while (current_state == FSMState::Established && is_active()) {
        struct pollfd pfd;
        pfd.fd = socket_fd;
        pfd.events = POLLIN;

        int poll_result = poll(&pfd, 1, keepalive_interval * 1000);

        if (poll_result < 0) {
            if (!is_active()) return;
            cout << log_prefix() << "ERROR: poll() failed ("
                 << strerror(errno) << ")" << endl;
            transition_to(FSMState::Idle, "Socket error");
            tcp_close();
            return;
        }

        if (poll_result > 0 && (pfd.revents & POLLIN)) {
            BGPHeader header;
            if (!read_header(header)) {
                transition_to(FSMState::Idle, "Connection lost");
                tcp_close();
                return;
            }

            if (header.type == BGP_MSG_KEEPALIVE) {
                cout << log_prefix() << "RECV: KEEPALIVE" << endl;

            } else if (header.type == BGP_MSG_NOTIFICATION) {
                uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
                if (payload_length >= 2) {
                    uint8_t notif_data[2];
                    read_bytes(notif_data, 2);
                    cout << log_prefix() << "RECV: NOTIFICATION (error="
                         << (int)notif_data[0] << ", subcode="
                         << (int)notif_data[1] << ")" << endl;
                } else {
                    cout << log_prefix() << "RECV: NOTIFICATION" << endl;
                }
                transition_to(FSMState::Idle, "Received NOTIFICATION from peer");
                tcp_close();
                return;

            } else if (header.type == BGP_MSG_UPDATE) {
                uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
                if (payload_length > 0) {
                    uint8_t payload[BGP_MAX_MESSAGE_SIZE];
                    if (!read_bytes(payload, payload_length)) {
                        transition_to(FSMState::Idle, "Connection lost during UPDATE");
                        tcp_close();
                        return;
                    }
                    process_update(payload, payload_length);
                }

            } else {
                cout << log_prefix() << "RECV: Unknown message type "
                     << (int)header.type << endl;
            }
        }

        if (current_state == FSMState::Established) {
            send_keepalive();
        }
    }
}


// Main per-peer run loop

void PeerSession::run() {
    PeerType peer_type = (peer.peer_as != speaker.get_config().local_as)
                         ? PeerType::EBGP : PeerType::IBGP;
    string peer_type_str = (peer_type == PeerType::EBGP) ? "eBGP" : "iBGP";

    cout << log_prefix() << "Peer thread started (AS "
         << peer.peer_as << ", " << peer_type_str << ")" << endl;

    int connect_retry_seconds = 10;

    while (is_active()) {
        current_state = FSMState::Idle;
        transition_to(FSMState::Connect, "ManualStart");

        handle_connect();

        if (current_state == FSMState::OpenSent)
            handle_open_sent();

        if (current_state == FSMState::OpenConfirm)
            handle_open_confirm();

        if (current_state == FSMState::Established)
            handle_established();

        if (is_active()) {
            if (socket_fd >= 0) {
                send_notification(ERR_CEASE, 0);
            }

            speaker.on_peer_down(peer_index);
            peer_supports_4byte_asn = false;

            tcp_close();
            cout << log_prefix() << "Session ended. Retrying in "
                 << connect_retry_seconds << " seconds..." << endl;
            for (int i = 0; i < connect_retry_seconds && is_active(); i++) {
                sleep(1);
            }
        }
    }

    if (current_state == FSMState::Established && socket_fd >= 0) {
        send_notification(ERR_CEASE, 0);
    }
    tcp_close();
}
