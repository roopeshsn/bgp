#include "speaker.h"
#include "update_encoder.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

using namespace std;

const string CLI_SOCKET_PATH = "/tmp/bgp_speaker.sock";


BGPSpeaker::BGPSpeaker(const SpeakerConfig& config, const vector<PeerConfig>& peers)
    : config(config), running(true), cli_sock_fd(-1),
      socket_path(CLI_SOCKET_PATH), static_rib_index(0) {

    // Static routes AdjRIBIn is always at index 0
    adj_rib_ins.emplace_back("local", config.local_as, PeerType::IBGP);
    static_rib_index = 0;

    // Add initial peers (indices start at 1)
    for (auto& p : peers) {
        PeerType pt = (p.peer_as != config.local_as) ? PeerType::EBGP : PeerType::IBGP;
        peer_configs.push_back(p);
        adj_rib_ins.emplace_back(p.peer_ip, p.peer_as, pt);
        sessions.push_back(make_unique<PeerSession>(*this, p, (int)adj_rib_ins.size() - 1));
        tx_routes.emplace_back();
    }
}

BGPSpeaker::~BGPSpeaker() {
    if (cli_sock_fd >= 0) {
        close(cli_sock_fd);
    }
    unlink(socket_path.c_str());
}

string BGPSpeaker::get_timestamp() {
    auto now = chrono::system_clock::now();
    time_t time = chrono::system_clock::to_time_t(now);
    struct tm local_time;
    localtime_r(&time, &local_time);

    char buffer[16];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &local_time);
    return string(buffer);
}

void BGPSpeaker::request_shutdown() {
    running.store(false, memory_order_relaxed);
}

bool BGPSpeaker::is_running() const {
    return running.load(memory_order_relaxed);
}

const SpeakerConfig& BGPSpeaker::get_config() const {
    return config;
}

string BGPSpeaker::origin_to_string(Origin origin) {
    switch (origin) {
        case Origin::IGP:        return "IGP";
        case Origin::EGP:        return "EGP";
        case Origin::INCOMPLETE: return "?";
    }
    return "?";
}

string BGPSpeaker::peer_type_to_string(PeerType pt) {
    return (pt == PeerType::EBGP) ? "eBGP" : "iBGP";
}


void BGPSpeaker::run() {
    cout << "[" << get_timestamp() << "] BGP Speaker starting (multi-peer)" << endl;
    cout << "[" << get_timestamp() << "] Local AS: " << config.local_as
         << ", Router ID: " << config.router_id << endl;
    cout << "[" << get_timestamp() << "] Peers: " << peer_configs.size()
         << " configured" << endl;

    for (auto& pc : peer_configs) {
        PeerType pt = (pc.peer_as != config.local_as) ? PeerType::EBGP : PeerType::IBGP;
        string pt_str = (pt == PeerType::EBGP) ? "eBGP" : "iBGP";
        cout << "[" << get_timestamp() << "]   " << pc.peer_ip
             << ":" << pc.peer_port
             << " (AS " << pc.peer_as << ", " << pt_str << ")" << endl;
    }

    if (!programmer.open()) {
        cout << "[" << get_timestamp() << "] WARNING: Could not open routing socket" << endl;
    }
    if (programmer.is_dry_run()) {
        cout << "[" << get_timestamp() << "] Mode: DRY-RUN (run with sudo for real routes)" << endl;
    } else {
        cout << "[" << get_timestamp() << "] Mode: LIVE ("
             << RouteProgrammer::platform_name() << ")" << endl;
    }

    cout << "[" << get_timestamp() << "] CLI socket: " << socket_path << endl;
    cout << endl;

    // Start peer threads
    for (int i = 0; i < (int)sessions.size(); i++) {
        threads.emplace_back(&PeerSession::run, sessions[i].get());
    }

    // Start CLI server thread
    cli_thread = thread(&BGPSpeaker::cli_server_loop, this);

    // Wait for shutdown signal
    while (running.load(memory_order_relaxed)) {
        sleep(1);
    }

    // Join all peer threads
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    // Wait for CLI server
    if (cli_thread.joinable()) {
        cli_thread.join();
    }

    cleanup_all_routes();
    programmer.close();
    cout << "\n[" << get_timestamp() << "] BGP Speaker stopped" << endl;
}


// CLI server (Unix domain socket)

void BGPSpeaker::cli_server_loop() {
    unlink(socket_path.c_str());

    cli_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cli_sock_fd < 0) {
        cout << "[" << get_timestamp() << "] WARNING: Failed to create CLI socket" << endl;
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(cli_sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        cout << "[" << get_timestamp() << "] WARNING: Failed to bind CLI socket" << endl;
        close(cli_sock_fd);
        cli_sock_fd = -1;
        return;
    }

    if (listen(cli_sock_fd, 1) < 0) {
        cout << "[" << get_timestamp() << "] WARNING: Failed to listen on CLI socket" << endl;
        close(cli_sock_fd);
        cli_sock_fd = -1;
        return;
    }

    while (running.load(memory_order_relaxed)) {
        struct pollfd pfd;
        pfd.fd = cli_sock_fd;
        pfd.events = POLLIN;

        int poll_result = poll(&pfd, 1, 1000);

        if (poll_result <= 0) continue;

        int client_fd = accept(cli_sock_fd, nullptr, nullptr);
        if (client_fd < 0) continue;

        // Handle one client connection
        char buf[4096];
        while (running.load(memory_order_relaxed)) {
            ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
            if (n <= 0) break;

            buf[n] = '\0';

            // Strip trailing newline
            string line(buf);
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
                line.pop_back();
            }

            if (line.empty()) continue;

            if (line == "exit" || line == "quit") {
                string bye = "Goodbye.\n\n";
                send(client_fd, bye.c_str(), bye.size(), 0);
                break;
            }

            string response = execute_command(line);
            response += "\n";
            send(client_fd, response.c_str(), response.size(), 0);
        }

        close(client_fd);
    }

    close(cli_sock_fd);
    cli_sock_fd = -1;
    unlink(socket_path.c_str());
}

string BGPSpeaker::execute_command(const string& line) {
    stringstream out;

    if (line == "help" || line == "?") {
        show_help(out);
    } else if (line == "show neighbors" || line == "show neighbor") {
        show_neighbors(out);
    } else if (line == "show brib") {
        show_brib(out);
    } else if (line == "show rib") {
        show_rib(out);
    } else if (line.substr(0, 9) == "show rib ") {
        show_rib_for_peer(out, line.substr(9));
    } else if (line == "show routes") {
        show_routes(out);
    } else if (line == "show summary") {
        show_summary(out);
    } else if (line.substr(0, 10) == "add route ") {
        string args = line.substr(10);
        size_t space = args.find(' ');
        if (space == string::npos) {
            out << "Usage: add route <prefix> <next-hop>" << endl;
        } else {
            add_static_route(out, args.substr(0, space), args.substr(space + 1));
        }
    } else if (line.substr(0, 15) == "withdraw route ") {
        withdraw_static_route(out, line.substr(15));
    } else if (line.substr(0, 9) == "add peer ") {
        string args = line.substr(9);
        istringstream iss(args);
        string ip;
        uint16_t port;
        uint32_t as_num;
        if (iss >> ip >> port >> as_num) {
            add_peer(out, ip, port, as_num);
        } else {
            out << "Usage: add peer <ip> <port> <as>" << endl;
        }
    } else if (line.substr(0, 12) == "remove peer ") {
        remove_peer(out, line.substr(12));
    } else {
        out << "Unknown command: " << line << endl;
        out << "Type 'help' for available commands." << endl;
    }

    return out.str();
}


// CLI command implementations

void BGPSpeaker::show_help(stringstream& out) {
    out << endl;
    out << "Available commands:" << endl;
    out << "  show neighbors          List all peers with state and route count" << endl;
    out << "  show brib               Show all routes from all peers (BRIB)" << endl;
    out << "  show rib                Show Loc-RIB (best routes)" << endl;
    out << "  show rib <peer_ip>      Show Adj-RIB-In for a specific peer" << endl;
    out << "  show routes             Show programmed kernel routes" << endl;
    out << "  show summary            One-line stats" << endl;
    out << "  add route <prefix> <nh> Inject a static route" << endl;
    out << "  withdraw route <prefix> Remove a static route" << endl;
    out << "  add peer <ip> <port> <as>  Add a new peer" << endl;
    out << "  remove peer <ip>:<port>    Remove a peer" << endl;
    out << "  help                    Show this help" << endl;
    out << "  exit                    Close CLI connection" << endl;
}

void BGPSpeaker::show_neighbors(stringstream& out) {
    lock_guard<mutex> lock(mtx);

    out << endl;
    out << "  " << left << setw(18) << "Neighbor"
        << setw(8) << "AS"
        << setw(8) << "Type"
        << setw(16) << "State"
        << right << setw(8) << "Rx"
        << right << setw(8) << "Tx" << endl;

    out << "  " << left << setw(18) << "--------"
        << setw(8) << "--"
        << setw(8) << "----"
        << setw(16) << "-----"
        << right << setw(8) << "--"
        << right << setw(8) << "--" << endl;

    for (int i = 0; i < (int)sessions.size(); i++) {
        PeerConfig pc = sessions[i]->get_peer_config();
        FSMState state = sessions[i]->get_state();
        PeerType pt = (pc.peer_as != config.local_as) ? PeerType::EBGP : PeerType::IBGP;

        string addr = pc.peer_ip + ":" + to_string(pc.peer_port);

        string state_str;
        switch (state) {
            case FSMState::Idle:        state_str = "Idle"; break;
            case FSMState::Connect:     state_str = "Connect"; break;
            case FSMState::Active:      state_str = "Active"; break;
            case FSMState::OpenSent:    state_str = "OpenSent"; break;
            case FSMState::OpenConfirm: state_str = "OpenConfirm"; break;
            case FSMState::Established: state_str = "Established"; break;
        }

        int rib_index = i + 1;

        out << "  " << left << setw(18) << addr
            << setw(8) << pc.peer_as
            << setw(8) << peer_type_to_string(pt)
            << setw(16) << state_str
            << right << setw(8) << adj_rib_ins[rib_index].route_count()
            << right << setw(8) << tx_routes[i].size() << endl;
    }
}

void BGPSpeaker::show_brib(stringstream& out) {
    lock_guard<mutex> lock(mtx);

    int total = 0;
    for (auto& rib : adj_rib_ins) total += rib.route_count();

    out << endl;
    if (total == 0) {
        out << "  BRIB is empty" << endl;
        return;
    }

    out << "  " << left << setw(22) << "Prefix"
        << setw(18) << "Next Hop"
        << setw(16) << "Peer"
        << setw(8) << "Origin"
        << setw(10) << "LocPref"
        << setw(8) << "MED"
        << "AS Path" << endl;

    out << "  " << left << setw(22) << "------"
        << setw(18) << "--------"
        << setw(16) << "----"
        << setw(8) << "------"
        << setw(10) << "-------"
        << setw(8) << "---"
        << "-------" << endl;

    for (auto& rib : adj_rib_ins) {
        vector<RIBEntry> routes = rib.get_all_routes();
        for (auto& entry : routes) {
            string as_path;
            for (size_t i = 0; i < entry.attributes.as_path.size(); i++) {
                if (i > 0) as_path += " ";
                as_path += to_string(entry.attributes.as_path[i]);
            }
            if (as_path.empty()) as_path = "-";

            out << "  " << left << setw(22) << entry.prefix.to_string()
                << setw(18) << entry.attributes.next_hop
                << setw(16) << entry.peer_ip
                << setw(8) << origin_to_string(entry.attributes.origin)
                << right << setw(7) << entry.attributes.local_pref << "   "
                << left << setw(8) << entry.attributes.med
                << as_path << endl;
        }
    }

    out << endl;
    out << "  Total: " << total << " routes from "
        << adj_rib_ins.size() << " sources" << endl;
}

void BGPSpeaker::show_rib(stringstream& out) {
    lock_guard<mutex> lock(mtx);

    vector<RIBEntry> routes = loc_rib.get_all_routes();

    out << endl;
    if (routes.empty()) {
        out << "  Loc-RIB is empty" << endl;
        return;
    }

    out << "  " << left << setw(22) << "Prefix"
        << setw(18) << "Next Hop"
        << setw(16) << "Peer"
        << setw(24) << "AS Path"
        << "Decisive Step" << endl;

    out << "  " << left << setw(22) << "------"
        << setw(18) << "--------"
        << setw(16) << "----"
        << setw(24) << "-------"
        << "-------------" << endl;

    for (auto& entry : routes) {
        string as_path;
        for (size_t i = 0; i < entry.attributes.as_path.size(); i++) {
            if (i > 0) as_path += " ";
            as_path += to_string(entry.attributes.as_path[i]);
        }
        if (as_path.empty()) as_path = "-";

        out << "  " << left << setw(22) << entry.prefix.to_string()
            << setw(18) << entry.attributes.next_hop
            << setw(16) << entry.peer_ip
            << setw(24) << as_path
            << entry.decisive_reason << endl;
    }
}

void BGPSpeaker::show_rib_for_peer(stringstream& out, const string& peer_ip) {
    lock_guard<mutex> lock(mtx);

    int rib_index = -1;

    if (peer_ip == "local") {
        rib_index = static_rib_index;
    } else {
        for (int i = 0; i < (int)peer_configs.size(); i++) {
            if (peer_configs[i].peer_ip == peer_ip) {
                rib_index = i + 1;
                break;
            }
        }
    }

    if (rib_index < 0) {
        out << "  Unknown peer: " << peer_ip << endl;
        return;
    }

    vector<RIBEntry> routes = adj_rib_ins[rib_index].get_all_routes();

    out << endl;
    if (routes.empty()) {
        out << "  Adj-RIB-In for " << peer_ip << " is empty" << endl;
        return;
    }

    out << "  Adj-RIB-In for " << peer_ip
        << " (" << routes.size() << " routes):" << endl;
    out << endl;

    out << "  " << left << setw(22) << "Prefix"
        << setw(18) << "Next Hop"
        << setw(8) << "Origin"
        << setw(10) << "LocPref"
        << setw(8) << "MED"
        << "AS Path" << endl;

    out << "  " << left << setw(22) << "------"
        << setw(18) << "--------"
        << setw(8) << "------"
        << setw(10) << "-------"
        << setw(8) << "---"
        << "-------" << endl;

    for (auto& entry : routes) {
        string as_path;
        for (size_t i = 0; i < entry.attributes.as_path.size(); i++) {
            if (i > 0) as_path += " ";
            as_path += to_string(entry.attributes.as_path[i]);
        }
        if (as_path.empty()) as_path = "-";

        out << "  " << left << setw(22) << entry.prefix.to_string()
            << setw(18) << entry.attributes.next_hop
            << setw(8) << origin_to_string(entry.attributes.origin)
            << right << setw(7) << entry.attributes.local_pref << "   "
            << left << setw(8) << entry.attributes.med
            << as_path << endl;
    }
}

void BGPSpeaker::show_routes(stringstream& out) {
    lock_guard<mutex> lock(mtx);

    out << endl;
    if (programmed_routes.empty()) {
        out << "  No routes programmed in kernel" << endl;
        return;
    }

    string mode = programmer.is_dry_run() ? " (dry-run)" : "";
    out << "  Kernel routes" << mode << ":" << endl;
    out << endl;

    out << "  " << left << setw(22) << "Prefix"
        << "Next Hop" << endl;

    out << "  " << left << setw(22) << "------"
        << "--------" << endl;

    for (auto& [key, route] : programmed_routes) {
        out << "  " << left << setw(22) << key
            << route.next_hop << endl;
    }
}

void BGPSpeaker::show_summary(stringstream& out) {
    lock_guard<mutex> lock(mtx);

    int peers_up = 0;
    for (auto& session : sessions) {
        if (session->get_state() == FSMState::Established) peers_up++;
    }

    int total_received = 0;
    for (auto& rib : adj_rib_ins) total_received += rib.route_count();

    out << "  Peers: " << peers_up << "/" << sessions.size() << " established"
        << "  Routes: " << total_received << " received, "
        << loc_rib.route_count() << " best, "
        << programmed_routes.size() << " programmed" << endl;
}

void BGPSpeaker::add_static_route(stringstream& out, const string& prefix_str,
                                   const string& next_hop) {
    size_t slash = prefix_str.find('/');
    if (slash == string::npos) {
        out << "  Invalid prefix format. Use: 10.0.0.0/24" << endl;
        return;
    }

    Prefix prefix;
    prefix.network = prefix_str.substr(0, slash);
    prefix.length = stoi(prefix_str.substr(slash + 1));

    PathAttributes attrs;
    attrs.origin = Origin::IGP;
    attrs.next_hop = next_hop;
    attrs.local_pref = 100;
    attrs.med = 0;
    attrs.atomic_aggregate = false;
    attrs.aggregator_as = 0;

    {
        lock_guard<mutex> lock(mtx);
        adj_rib_ins[static_rib_index].add_route(prefix, attrs, 32768, true);
        run_selection_and_program();
    }

    out << "  Added static route: " << prefix_str << " via " << next_hop << endl;
}

void BGPSpeaker::withdraw_static_route(stringstream& out, const string& prefix_str) {
    size_t slash = prefix_str.find('/');
    if (slash == string::npos) {
        out << "  Invalid prefix format. Use: 10.0.0.0/24" << endl;
        return;
    }

    Prefix prefix;
    prefix.network = prefix_str.substr(0, slash);
    prefix.length = stoi(prefix_str.substr(slash + 1));

    {
        lock_guard<mutex> lock(mtx);
        adj_rib_ins[static_rib_index].withdraw_route(prefix);
        run_selection_and_program();
    }

    out << "  Withdrawn static route: " << prefix_str << endl;
}

void BGPSpeaker::start_peer(const PeerConfig& peer) {
    int index = (int)adj_rib_ins.size();
    PeerType pt = (peer.peer_as != config.local_as) ? PeerType::EBGP : PeerType::IBGP;

    peer_configs.push_back(peer);
    adj_rib_ins.emplace_back(peer.peer_ip, peer.peer_as, pt);
    tx_routes.emplace_back();
    sessions.push_back(make_unique<PeerSession>(*this, peer, index));
    threads.emplace_back(&PeerSession::run, sessions.back().get());
}

void BGPSpeaker::add_peer(stringstream& out, const string& ip, uint16_t port, uint32_t as_num) {
    lock_guard<mutex> lock(mtx);

    string addr = ip + ":" + to_string(port);

    for (auto& pc : peer_configs) {
        if (pc.peer_ip == ip && pc.peer_port == port) {
            out << "  Peer " << addr << " already exists" << endl;
            return;
        }
    }

    PeerConfig peer;
    peer.peer_ip = ip;
    peer.peer_port = port;
    peer.peer_as = as_num;

    start_peer(peer);

    out << "  Added peer " << addr << " AS " << as_num << endl;
}

void BGPSpeaker::remove_peer(stringstream& out, const string& addr) {
    lock_guard<mutex> lock(mtx);

    int found = -1;
    for (int i = 0; i < (int)peer_configs.size(); i++) {
        string peer_addr = peer_configs[i].peer_ip + ":" + to_string(peer_configs[i].peer_port);
        if (peer_addr == addr || peer_configs[i].peer_ip == addr) {
            found = i;
            break;
        }
    }

    if (found < 0) {
        out << "  Unknown peer: " << addr << endl;
        return;
    }

    string peer_addr = peer_configs[found].peer_ip + ":"
                     + to_string(peer_configs[found].peer_port);

    sessions[found]->request_stop();

    int rib_index = found + 1;
    PeerType pt = (peer_configs[found].peer_as != config.local_as)
                  ? PeerType::EBGP : PeerType::IBGP;
    adj_rib_ins[rib_index] = AdjRIBIn(
        peer_configs[found].peer_ip,
        peer_configs[found].peer_as, pt);
    tx_routes[found].clear();

    run_selection_and_program();

    out << "  Removed peer " << peer_addr << endl;
}


// Thread-safe callbacks from PeerSession

void BGPSpeaker::apply_update(int peer_index, const ParsedUpdate& update) {
    lock_guard<mutex> lock(mtx);

    for (auto& prefix : update.withdrawn_routes) {
        adj_rib_ins[peer_index].withdraw_route(prefix);
    }

    for (auto& prefix : update.nlri) {
        adj_rib_ins[peer_index].add_route(prefix, update.attributes, 0, false);
    }

    run_selection_and_program();

    int total_received = 0;
    for (auto& rib : adj_rib_ins) total_received += rib.route_count();
    cout << "[" << get_timestamp() << "] RIB: "
         << total_received << " received, "
         << loc_rib.route_count() << " best, "
         << programmed_routes.size() << " programmed" << endl;
}

void BGPSpeaker::on_peer_down(int peer_index) {
    lock_guard<mutex> lock(mtx);

    int pc_index = peer_index - 1;
    if (pc_index < 0 || pc_index >= (int)peer_configs.size()) return;

    PeerType pt = (peer_configs[pc_index].peer_as != config.local_as)
                  ? PeerType::EBGP : PeerType::IBGP;
    adj_rib_ins[peer_index] = AdjRIBIn(
        peer_configs[pc_index].peer_ip,
        peer_configs[pc_index].peer_as, pt);
    if (pc_index < (int)tx_routes.size()) {
        tx_routes[pc_index].clear();
    }

    run_selection_and_program();

    int total_received = 0;
    for (auto& rib : adj_rib_ins) total_received += rib.route_count();
    cout << "[" << get_timestamp() << "] [" << peer_configs[pc_index].peer_ip
         << "] Peer down. RIB: " << total_received << " received, "
         << loc_rib.route_count() << " best, "
         << programmed_routes.size() << " programmed" << endl;
}


// Route selection and kernel programming (called with mtx held)

void BGPSpeaker::run_selection_and_program() {
    vector<RIBEntry> old_best = loc_rib.get_all_routes();
    map<string, RIBEntry> old_best_map;
    for (auto& entry : old_best) {
        old_best_map[entry.prefix.to_string()] = entry;
    }

    loc_rib.run_best_path_selection(adj_rib_ins);

    vector<RIBEntry> new_best = loc_rib.get_all_routes();

    vector<RIBEntry> added_routes;
    vector<Prefix> withdrawn_prefixes;

    for (auto& entry : new_best) {
        string key = entry.prefix.to_string();
        auto it = old_best_map.find(key);

        if (it == old_best_map.end()) {
            program_route_add(entry);
            added_routes.push_back(entry);
        } else if (it->second.attributes.next_hop != entry.attributes.next_hop) {
            program_route_delete(key);
            program_route_add(entry);
            added_routes.push_back(entry);
        }
        old_best_map.erase(key);
    }

    for (auto& [key, entry] : old_best_map) {
        program_route_delete(key);
        withdrawn_prefixes.push_back(entry.prefix);
    }

    advertise_to_peers(added_routes, withdrawn_prefixes);
}

void BGPSpeaker::advertise_to_peers(const vector<RIBEntry>& added,
                                     const vector<Prefix>& withdrawn) {
    for (int i = 0; i < (int)sessions.size(); i++) {
        if (sessions[i]->get_state() != FSMState::Established) continue;

        string peer_ip = peer_configs[i].peer_ip;

        // Send withdrawals
        if (!withdrawn.empty()) {
            vector<Prefix> withdraw_for_peer;
            for (auto& prefix : withdrawn) {
                string key = prefix.to_string();
                if (tx_routes[i].count(key)) {
                    withdraw_for_peer.push_back(prefix);
                    tx_routes[i].erase(key);
                }
            }
            if (!withdraw_for_peer.empty()) {
                vector<uint8_t> msg = encode_withdraw(withdraw_for_peer);
                if (sessions[i]->send_update(msg)) {
                    cout << "[" << get_timestamp() << "] [" << peer_ip
                         << "] SENT: WITHDRAW " << withdraw_for_peer.size()
                         << " prefixes" << endl;
                }
            }
        }

        // Send advertisements with split horizon
        vector<Prefix> nlri_for_peer;
        PathAttributes attrs_for_peer;
        bool has_attrs = false;

        for (auto& entry : added) {
            if (entry.peer_ip == peer_ip) continue;

            if (!has_attrs) {
                attrs_for_peer = entry.attributes;
                attrs_for_peer.as_path.insert(
                    attrs_for_peer.as_path.begin(), config.local_as);
                has_attrs = true;
            }

            nlri_for_peer.push_back(entry.prefix);
        }

        if (!nlri_for_peer.empty()) {
            vector<uint8_t> msg = encode_update(attrs_for_peer, nlri_for_peer);
            if (sessions[i]->send_update(msg)) {
                for (auto& prefix : nlri_for_peer) {
                    tx_routes[i].insert(prefix.to_string());
                }
                cout << "[" << get_timestamp() << "] [" << peer_ip
                     << "] SENT: UPDATE " << nlri_for_peer.size()
                     << " prefixes" << endl;
            }
        }
    }
}

void BGPSpeaker::program_route_add(const RIBEntry& entry) {
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

void BGPSpeaker::program_route_delete(const string& prefix_key) {
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

void BGPSpeaker::cleanup_all_routes() {
    lock_guard<mutex> lock(mtx);

    if (programmed_routes.empty()) return;

    cout << "[" << get_timestamp() << "] Cleaning up "
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
