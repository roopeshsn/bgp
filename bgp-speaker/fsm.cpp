#include "fsm.h"
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


BGPFiniteStateMachine::BGPFiniteStateMachine(const FSMConfig& config)
    : config(config),
      current_state(FSMState::Idle),
      socket_fd(-1),
      negotiated_hold_time(0),
      running(true),
      adj_rib_in(config.peer_ip, config.peer_as,
                 (config.peer_as != config.local_as) ? PeerType::EBGP : PeerType::IBGP),
      peer_supports_4byte_asn(false) {
}

BGPFiniteStateMachine::~BGPFiniteStateMachine() {
    tcp_close();
}

void BGPFiniteStateMachine::shutdown() {
    if (!running) return;
    running = false;

    if (!programmed_routes.empty()) {
        cout << "\n[" << get_timestamp() << "] Cleaning up "
             << programmed_routes.size() << " programmed routes..." << endl;
        for (auto& [key, route] : programmed_routes) {
            ProgramResult result = programmer.delete_route(route);
            string status = result.success ? "OK" : result.error;
            if (programmer.is_dry_run() && result.success) status = "OK (dry-run)";
            cout << "[" << get_timestamp() << "] DEL: " << key
                 << " ... " << status << endl;
        }
        programmed_routes.clear();
    }

    if (current_state == FSMState::Established && socket_fd >= 0) {
        cout << "[" << get_timestamp() << "] Initiating graceful shutdown" << endl;
        send_notification(ERR_CEASE, 0);
        transition_to(FSMState::Idle, "Administrative shutdown");
    }
    tcp_close();
    programmer.close();
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

string BGPFiniteStateMachine::as_path_to_string(const vector<uint32_t>& as_path) {
    string result;
    for (size_t i = 0; i < as_path.size(); i++) {
        if (i > 0) result += " ";
        result += to_string(as_path[i]);
    }
    return result;
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


// Message sending

void BGPFiniteStateMachine::send_open() {
    uint8_t message[64];
    int offset = 0;

    memset(message, 0xFF, BGP_MARKER_LENGTH);
    offset += BGP_MARKER_LENGTH;

    int length_offset = offset;
    offset += 2;

    message[offset++] = BGP_MSG_OPEN;

    message[offset++] = BGP_VERSION;

    uint16_t my_as = (uint16_t)config.local_as;
    message[offset++] = (my_as >> 8) & 0xFF;
    message[offset++] = my_as & 0xFF;

    message[offset++] = (config.hold_time >> 8) & 0xFF;
    message[offset++] = config.hold_time & 0xFF;

    uint32_t bgp_id = ip_to_uint32(config.router_id);
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
    message[offset++] = 1;    // AFI: IPv4
    message[offset++] = 0;
    message[offset++] = 1;    // SAFI: Unicast

    // 4-Byte ASN
    message[offset++] = 2;
    message[offset++] = 6;
    message[offset++] = 65;
    message[offset++] = 4;
    message[offset++] = (config.local_as >> 24) & 0xFF;
    message[offset++] = (config.local_as >> 16) & 0xFF;
    message[offset++] = (config.local_as >> 8) & 0xFF;
    message[offset++] = config.local_as & 0xFF;

    int opt_params_length = offset - opt_params_start;
    message[opt_params_length_offset] = opt_params_length;

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

void BGPFiniteStateMachine::send_keepalive() {
    uint8_t message[19];
    int offset = 0;

    memset(message, 0xFF, BGP_MARKER_LENGTH);
    offset += BGP_MARKER_LENGTH;

    uint16_t length = BGP_HEADER_LENGTH;
    message[offset++] = (length >> 8) & 0xFF;
    message[offset++] = length & 0xFF;

    message[offset++] = BGP_MSG_KEEPALIVE;

    send_bytes(message, offset);
    cout << "[" << get_timestamp() << "] SEND: KEEPALIVE\n";
}

void BGPFiniteStateMachine::send_notification(uint8_t error_code, uint8_t error_subcode) {
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
    cout << "[" << get_timestamp() << "] SEND: NOTIFICATION (error="
         << (int)error_code << ", subcode=" << (int)error_subcode << ")" << endl;
}


// Message receiving

bool BGPFiniteStateMachine::read_header(BGPHeader& header) {
    uint8_t buffer[BGP_HEADER_LENGTH];

    if (!read_bytes(buffer, BGP_HEADER_LENGTH)) return false;

    for (int i = 0; i < BGP_MARKER_LENGTH; i++) {
        if (buffer[i] != 0xFF) {
            cout << "[" << get_timestamp() << "] ERROR: Invalid BGP marker\n";
            return false;
        }
    }

    header.length = (buffer[16] << 8) | buffer[17];
    header.type = buffer[18];

    return true;
}

bool BGPFiniteStateMachine::read_open_message(uint16_t payload_length, BGPOpenMessage& open_msg) {
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
                    peer_supports_4byte_asn = true;
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


// UPDATE processing pipeline

void BGPFiniteStateMachine::process_update(const uint8_t* payload, uint16_t payload_length) {
    ParsedUpdate update;
    if (!parse_update(payload, payload_length, update)) {
        cout << "[" << get_timestamp() << "] ERROR: Failed to parse UPDATE" << endl;
        return;
    }

    // End-of-RIB marker
    if (update.withdrawn_routes.empty() && update.nlri.empty()) {
        cout << "[" << get_timestamp() << "] RECV: End-of-RIB marker" << endl;
        return;
    }

    // Process withdrawals
    for (auto& prefix : update.withdrawn_routes) {
        cout << "[" << get_timestamp() << "] WITHDRAW: " << prefix.to_string() << endl;
        adj_rib_in.withdraw_route(prefix);
    }

    // Process NLRI
    for (auto& prefix : update.nlri) {
        cout << "[" << get_timestamp() << "] NLRI: " << prefix.to_string()
             << " via " << update.attributes.next_hop
             << " AS_PATH [" << as_path_to_string(update.attributes.as_path) << "]" << endl;
        adj_rib_in.add_route(prefix, update.attributes, 0, false);
    }

    // Snapshot current Loc-RIB
    vector<RIBEntry> old_best = loc_rib.get_all_routes();
    map<string, RIBEntry> old_best_map;
    for (auto& entry : old_best) {
        old_best_map[entry.prefix.to_string()] = entry;
    }

    // Run best path selection
    vector<AdjRIBIn> rib_ins = {adj_rib_in};
    loc_rib.run_best_path_selection(rib_ins);

    // Diff and program kernel
    vector<RIBEntry> new_best = loc_rib.get_all_routes();

    for (auto& entry : new_best) {
        string key = entry.prefix.to_string();
        auto it = old_best_map.find(key);

        if (it == old_best_map.end()) {
            program_route_add(entry);
        } else if (it->second.attributes.next_hop != entry.attributes.next_hop) {
            program_route_delete(key);
            program_route_add(entry);
        }
        old_best_map.erase(key);
    }

    // Remove routes no longer in Loc-RIB
    for (auto& [key, entry] : old_best_map) {
        program_route_delete(key);
    }

    cout << "[" << get_timestamp() << "] RIB: "
         << adj_rib_in.route_count() << " received, "
         << loc_rib.route_count() << " best, "
         << programmed_routes.size() << " programmed" << endl;
}

void BGPFiniteStateMachine::program_route_add(const RIBEntry& entry) {
    KernelRoute route;
    route.prefix = entry.prefix;
    route.next_hop = entry.attributes.next_hop;
    route.state = RouteState::PENDING;

    ProgramResult result = programmer.add_route(route);
    string key = entry.prefix.to_string();

    if (result.success) {
        programmed_routes[key] = route;
        string mode = programmer.is_dry_run() ? " (dry-run)" : "";
        cout << "[" << get_timestamp() << "] KERNEL ADD: " << key
             << " via " << entry.attributes.next_hop << mode << endl;
    } else {
        cout << "[" << get_timestamp() << "] KERNEL ADD FAILED: " << key
             << " - " << result.error << endl;
    }
}

void BGPFiniteStateMachine::program_route_delete(const string& prefix_key) {
    auto it = programmed_routes.find(prefix_key);
    if (it == programmed_routes.end()) return;

    ProgramResult result = programmer.delete_route(it->second);
    if (result.success) {
        string mode = programmer.is_dry_run() ? " (dry-run)" : "";
        cout << "[" << get_timestamp() << "] KERNEL DEL: " << prefix_key << mode << endl;
        programmed_routes.erase(it);
    } else {
        cout << "[" << get_timestamp() << "] KERNEL DEL FAILED: " << prefix_key
             << " - " << result.error << endl;
    }
}


// FSM state handlers

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

    if (peer_open.version != BGP_VERSION) {
        cout << "[" << get_timestamp() << "] ERROR: Unsupported BGP version "
             << (int)peer_open.version << endl;
        send_notification(ERR_OPEN_MESSAGE, 1);
        transition_to(FSMState::Idle, "Unsupported BGP version");
        tcp_close();
        return;
    }

    negotiated_hold_time = config.hold_time;
    if (peer_open.hold_time < negotiated_hold_time) {
        negotiated_hold_time = peer_open.hold_time;
    }
    cout << "[" << get_timestamp() << "] Negotiated hold time: "
         << negotiated_hold_time << " seconds\n";

    transition_to(FSMState::OpenConfirm, "Valid OPEN received");
    send_keepalive();
}

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

    if (header.type == BGP_MSG_OPEN) {
        uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
        uint8_t discard[BGP_MAX_MESSAGE_SIZE];
        read_bytes(discard, payload_length);
        handle_open_confirm();
        return;
    }

    cout << "[" << get_timestamp() << "] ERROR: Expected KEEPALIVE, got type "
         << (int)header.type << endl;
    send_notification(ERR_FSM, 0);
    transition_to(FSMState::Idle, "Unexpected message type");
    tcp_close();
}

void BGPFiniteStateMachine::handle_established() {
    cout << "[" << get_timestamp() << "] === BGP Session Established ===" << endl;

    int keepalive_interval = negotiated_hold_time / 3;
    if (keepalive_interval < 1) keepalive_interval = 1;

    cout << "[" << get_timestamp() << "] Keepalive interval: "
         << keepalive_interval << " seconds" << endl;

    while (current_state == FSMState::Established && running) {
        struct pollfd pfd;
        pfd.fd = socket_fd;
        pfd.events = POLLIN;

        int poll_result = poll(&pfd, 1, keepalive_interval * 1000);

        if (poll_result < 0) {
            if (!running) return;
            cout << "[" << get_timestamp() << "] ERROR: poll() failed ("
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
                cout << "[" << get_timestamp() << "] RECV: KEEPALIVE" << endl;

            } else if (header.type == BGP_MSG_NOTIFICATION) {
                uint16_t payload_length = header.length - BGP_HEADER_LENGTH;
                if (payload_length >= 2) {
                    uint8_t notif_data[2];
                    read_bytes(notif_data, 2);
                    cout << "[" << get_timestamp() << "] RECV: NOTIFICATION (error="
                         << (int)notif_data[0] << ", subcode="
                         << (int)notif_data[1] << ")" << endl;
                } else {
                    cout << "[" << get_timestamp() << "] RECV: NOTIFICATION" << endl;
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
                cout << "[" << get_timestamp() << "] RECV: Unknown message type "
                     << (int)header.type << endl;
            }
        }

        if (current_state == FSMState::Established) {
            send_keepalive();
        }
    }
}


// Main FSM run loop

void BGPFiniteStateMachine::run() {
    PeerType peer_type = (config.peer_as != config.local_as) ? PeerType::EBGP : PeerType::IBGP;
    string peer_type_str = (peer_type == PeerType::EBGP) ? "eBGP" : "iBGP";

    cout << "[" << get_timestamp() << "] BGP Speaker starting" << endl;
    cout << "[" << get_timestamp() << "] Local AS: " << config.local_as
         << ", Router ID: " << config.router_id << endl;
    cout << "[" << get_timestamp() << "] Peer: " << config.peer_ip
         << ":" << config.peer_port
         << " (AS " << config.peer_as << ", " << peer_type_str << ")" << endl;

    if (!programmer.open()) {
        cout << "[" << get_timestamp() << "] WARNING: Could not open routing socket" << endl;
    }
    if (programmer.is_dry_run()) {
        cout << "[" << get_timestamp() << "] Mode: DRY-RUN (run with sudo for real routes)" << endl;
    } else {
        cout << "[" << get_timestamp() << "] Mode: LIVE ("
             << RouteProgrammer::platform_name() << ")" << endl;
    }
    cout << endl;

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

        if (running) {
            // Send CEASE notification so the peer clears the session
            if (socket_fd >= 0) {
                send_notification(ERR_CEASE, 0);
            }

            // Clean up routes on session drop
            for (auto& [key, route] : programmed_routes) {
                programmer.delete_route(route);
                string mode = programmer.is_dry_run() ? " (dry-run)" : "";
                cout << "[" << get_timestamp() << "] KERNEL DEL: " << key
                     << mode << endl;
            }
            programmed_routes.clear();

            // Reset RIB state
            adj_rib_in = AdjRIBIn(config.peer_ip, config.peer_as,
                                  (config.peer_as != config.local_as) ?
                                  PeerType::EBGP : PeerType::IBGP);
            loc_rib = LocRIB();
            peer_supports_4byte_asn = false;

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
