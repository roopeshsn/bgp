#ifndef SPEAKER_H
#define SPEAKER_H

#include "bgp_types.h"
#include "rib.h"
#include "route_programmer.h"
#include "peer_session.h"
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>

using namespace std;


class BGPSpeaker {
public:
    BGPSpeaker(const SpeakerConfig& config, const vector<PeerConfig>& peers);
    ~BGPSpeaker();

    void run();
    void request_shutdown();
    bool is_running() const;
    const SpeakerConfig& get_config() const;

    void apply_update(int peer_index, const ParsedUpdate& update);
    void on_peer_down(int peer_index);

private:
    SpeakerConfig config;
    vector<PeerConfig> peer_configs;
    atomic<bool> running;

    mutable mutex mtx;
    vector<AdjRIBIn> adj_rib_ins;
    LocRIB loc_rib;
    RouteProgrammer programmer;
    map<string, KernelRoute> programmed_routes;

    vector<unique_ptr<PeerSession>> sessions;
    vector<thread> threads;

    int static_rib_index;
    vector<set<string>> tx_routes;

    void run_selection_and_program();
    void program_route_add(const RIBEntry& entry);
    void program_route_delete(const string& prefix_key);
    void cleanup_all_routes();
    void advertise_to_peers(const vector<RIBEntry>& added, const vector<Prefix>& withdrawn);
    void start_peer(const PeerConfig& peer);

    // CLI server (Unix socket)
    int cli_sock_fd;
    thread cli_thread;
    string socket_path;
    void cli_server_loop();
    string execute_command(const string& line);

    void show_help(stringstream& out);
    void show_neighbors(stringstream& out);
    void show_brib(stringstream& out);
    void show_rib(stringstream& out);
    void show_rib_for_peer(stringstream& out, const string& peer_ip);
    void show_routes(stringstream& out);
    void show_summary(stringstream& out);
    void add_static_route(stringstream& out, const string& prefix_str, const string& next_hop);
    void withdraw_static_route(stringstream& out, const string& prefix_str);
    void add_peer(stringstream& out, const string& ip, uint16_t port, uint32_t as_num);
    void remove_peer(stringstream& out, const string& addr);

    string origin_to_string(Origin origin);
    string peer_type_to_string(PeerType pt);
    string get_timestamp();
};

#endif
