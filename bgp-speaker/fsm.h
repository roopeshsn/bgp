#ifndef FSM_H
#define FSM_H

#include "bgp_types.h"
#include "rib.h"
#include "route_programmer.h"
#include <map>

using namespace std;


class BGPFiniteStateMachine {
public:
    BGPFiniteStateMachine(const FSMConfig& config);
    ~BGPFiniteStateMachine();

    void run();
    void shutdown();

private:
    FSMConfig config;
    FSMState current_state;
    int socket_fd;
    uint16_t negotiated_hold_time;
    volatile bool running;

    // RIB and route programming
    AdjRIBIn adj_rib_in;
    LocRIB loc_rib;
    RouteProgrammer programmer;
    map<string, KernelRoute> programmed_routes;

    bool peer_supports_4byte_asn;

    // State transition logging
    void transition_to(FSMState new_state, const string& reason);
    string state_to_string(FSMState state);
    string get_timestamp();

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

    // UPDATE processing pipeline
    void process_update(const uint8_t* payload, uint16_t payload_length);
    void program_route_add(const RIBEntry& entry);
    void program_route_delete(const string& prefix_key);

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
