#ifndef RIB_H
#define RIB_H

#include "bgp_types.h"
#include <map>
#include <vector>

using namespace std;


class AdjRIBIn {
public:
    AdjRIBIn(const string& peer_ip, uint32_t peer_as, PeerType peer_type);

    void add_route(const Prefix& prefix, const PathAttributes& attributes,
                   uint32_t weight, bool locally_originated);
    void withdraw_route(const Prefix& prefix);
    vector<RIBEntry> get_all_routes() const;
    int route_count() const;

    string get_peer_ip() const;
    uint32_t get_peer_as() const;
    PeerType get_peer_type() const;

private:
    string peer_ip;
    uint32_t peer_as;
    PeerType peer_type;
    map<string, RIBEntry> routes;

    string prefix_to_key(const Prefix& prefix) const;
};


class LocRIB {
public:
    void run_best_path_selection(const vector<AdjRIBIn>& adj_rib_ins);
    vector<RIBEntry> get_all_routes() const;
    int route_count() const;

private:
    map<string, RIBEntry> routes;

    string prefix_to_key(const Prefix& prefix) const;

    RIBEntry select_best(const vector<RIBEntry>& candidates) const;
    vector<RIBEntry> filter_by_weight(const vector<RIBEntry>& candidates) const;
    vector<RIBEntry> filter_by_local_pref(const vector<RIBEntry>& candidates) const;
    vector<RIBEntry> filter_by_locally_originated(const vector<RIBEntry>& candidates) const;
    vector<RIBEntry> filter_by_as_path_length(const vector<RIBEntry>& candidates) const;
    vector<RIBEntry> filter_by_origin(const vector<RIBEntry>& candidates) const;
    vector<RIBEntry> filter_by_med(const vector<RIBEntry>& candidates) const;
    vector<RIBEntry> filter_by_peer_type(const vector<RIBEntry>& candidates) const;
};

#endif
