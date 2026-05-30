#ifndef FSM_H
#define FSM_H

#include "bgp_types.h"

class BGPFiniteStateMachine {
public:
    BGPFiniteStateMachine(const FSMConfig& config);
    ~BGPFiniteStateMachine();

    // Start the FSM — connects to peer, performs handshake,
    // and enters keepalive loop until session ends.
    void run();

    // Gracefully shut down the session by sending a NOTIFICATION (Cease)
    // before closing the TCP connection. Called from the signal handler.
    void shutdown();

private:
    FSMConfig config;
    FSMState current_state;
    int socket_fd;
    uint16_t negotiated_hold_time;
    volatile bool running;

    // State transition logging
    void transition_to(FSMState new_state, const string& reason);
    string state_to_string(FSMState state);
    string get_timestamp();

    // TCP operations
    bool tcp_connect();
    void tcp_close();
    bool send_bytes(const uint8_t* data, int length);
    bool read_bytes(uint8_t* buffer, int length);

    // Message sending (wire format)
    void send_open();
    void send_keepalive();
    void send_notification(uint8_t error_code, uint8_t error_subcode);

    // Message receiving (wire format parsing)
    bool read_header(BGPHeader& header);
    bool read_open_message(uint16_t payload_length, BGPOpenMessage& open_msg);
    void parse_capabilities(const uint8_t* data, int length);

    // IPv4 string to 32-bit integer (e.g., "10.0.0.1" -> 0x0A000001)
    uint32_t ip_to_uint32(const string& ip);
    string uint32_to_ip(uint32_t ip);

    // FSM state handlers
    void handle_connect();
    void handle_open_sent();
    void handle_open_confirm();
    void handle_established();
};

#endif
