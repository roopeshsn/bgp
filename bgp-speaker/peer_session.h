#ifndef PEER_SESSION_H
#define PEER_SESSION_H

#include "bgp_types.h"
#include <vector>
#include <atomic>

using namespace std;

class BGPSpeaker;

class PeerSession {
public:
    PeerSession(BGPSpeaker& speaker, const PeerConfig& peer, int peer_index);
    void run();

    FSMState get_state() const;
    const PeerConfig& get_peer_config() const;
    bool send_update(const vector<uint8_t>& message);
    void request_stop();
    bool is_active() const;

private:
    BGPSpeaker& speaker;
    PeerConfig peer;
    int peer_index;

    FSMState current_state;
    int socket_fd;
    uint16_t negotiated_hold_time;
    bool peer_supports_4byte_asn;
    atomic<bool> removed;

    // State transition
    void transition_to(FSMState new_state, const string& reason);
    string state_to_string(FSMState state);
    string get_timestamp();
    string log_prefix();

    // TCP operations
    bool tcp_connect();
    void tcp_close();
    bool send_bytes(const uint8_t* data, int length);
    bool read_bytes(uint8_t* buffer, int length);

    // Message sending
    void send_open();
    void send_keepalive();
    void send_notification(uint8_t error_code, uint8_t error_subcode);

    // Message receiving
    bool read_header(BGPHeader& header);
    bool read_open_message(uint16_t payload_length, BGPOpenMessage& open_msg);
    void parse_capabilities(const uint8_t* data, int length);

    // UPDATE processing
    void process_update(const uint8_t* payload, uint16_t payload_length);

    // Utility
    uint32_t ip_to_uint32(const string& ip);
    string uint32_to_ip(uint32_t ip);
    string as_path_to_string(const vector<uint32_t>& as_path);

    // FSM state handlers
    void handle_connect();
    void handle_open_sent();
    void handle_open_confirm();
    void handle_established();
};

#endif
