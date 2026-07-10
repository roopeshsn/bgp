#include "rib.h"
#include <unordered_map>

using namespace std;


// ---------------------------------------------------------------
// Adj-RIB-In
// ---------------------------------------------------------------

AdjRIBIn::AdjRIBIn(const string& peer_ip, uint32_t peer_as, PeerType peer_type)
    : peer_ip(peer_ip), peer_as(peer_as), peer_type(peer_type) {
}

string AdjRIBIn::prefix_to_key(const Prefix& prefix) const {
    return prefix.network + "/" + to_string(prefix.length);
}

void AdjRIBIn::add_route(const Prefix& prefix, const PathAttributes& attributes,
                         uint32_t weight, bool locally_originated) {
    RIBEntry entry;
    entry.prefix = prefix;
    entry.attributes = attributes;
    entry.weight = weight;
    entry.peer_type = peer_type;
    entry.neighbor_as = peer_as;
    entry.locally_originated = locally_originated;
    entry.peer_ip = peer_ip;
    entry.is_best = false;
    entry.decisive_step = 0;
    entry.decisive_reason = "";

    string key = prefix_to_key(prefix);
    routes[key] = entry;
}

void AdjRIBIn::withdraw_route(const Prefix& prefix) {
    string key = prefix_to_key(prefix);
    routes.erase(key);
}

vector<RIBEntry> AdjRIBIn::get_all_routes() const {
    vector<RIBEntry> result;
    for (auto it = routes.begin(); it != routes.end(); it++) {
        result.push_back(it->second);
    }
    return result;
}

int AdjRIBIn::route_count() const {
    return routes.size();
}

string AdjRIBIn::get_peer_ip() const { return peer_ip; }
uint32_t AdjRIBIn::get_peer_as() const { return peer_as; }
PeerType AdjRIBIn::get_peer_type() const { return peer_type; }


// ---------------------------------------------------------------
// Loc-RIB — best path selection
// ---------------------------------------------------------------

string LocRIB::prefix_to_key(const Prefix& prefix) const {
    return prefix.network + "/" + to_string(prefix.length);
}

vector<RIBEntry> LocRIB::filter_by_weight(const vector<RIBEntry>& candidates) const {
    uint32_t highest = 0;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].weight > highest) highest = candidates[i].weight;
    }
    vector<RIBEntry> result;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].weight == highest) result.push_back(candidates[i]);
    }
    return result;
}

vector<RIBEntry> LocRIB::filter_by_local_pref(const vector<RIBEntry>& candidates) const {
    uint32_t highest = 0;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].attributes.local_pref > highest)
            highest = candidates[i].attributes.local_pref;
    }
    vector<RIBEntry> result;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].attributes.local_pref == highest) result.push_back(candidates[i]);
    }
    return result;
}

vector<RIBEntry> LocRIB::filter_by_locally_originated(const vector<RIBEntry>& candidates) const {
    bool any_local = false;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].locally_originated) { any_local = true; break; }
    }
    if (!any_local) return candidates;

    vector<RIBEntry> result;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].locally_originated) result.push_back(candidates[i]);
    }
    return result;
}

vector<RIBEntry> LocRIB::filter_by_as_path_length(const vector<RIBEntry>& candidates) const {
    size_t shortest = candidates[0].attributes.as_path.size();
    for (size_t i = 1; i < candidates.size(); i++) {
        if (candidates[i].attributes.as_path.size() < shortest)
            shortest = candidates[i].attributes.as_path.size();
    }
    vector<RIBEntry> result;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].attributes.as_path.size() == shortest) result.push_back(candidates[i]);
    }
    return result;
}

vector<RIBEntry> LocRIB::filter_by_origin(const vector<RIBEntry>& candidates) const {
    int lowest = static_cast<int>(candidates[0].attributes.origin);
    for (size_t i = 1; i < candidates.size(); i++) {
        int val = static_cast<int>(candidates[i].attributes.origin);
        if (val < lowest) lowest = val;
    }
    vector<RIBEntry> result;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (static_cast<int>(candidates[i].attributes.origin) == lowest)
            result.push_back(candidates[i]);
    }
    return result;
}

vector<RIBEntry> LocRIB::filter_by_med(const vector<RIBEntry>& candidates) const {
    unordered_map<uint32_t, vector<RIBEntry>> groups;
    for (size_t i = 0; i < candidates.size(); i++) {
        groups[candidates[i].neighbor_as].push_back(candidates[i]);
    }

    vector<RIBEntry> result;
    for (auto it = groups.begin(); it != groups.end(); it++) {
        vector<RIBEntry>& group = it->second;
        uint32_t lowest_med = group[0].attributes.med;
        for (size_t i = 1; i < group.size(); i++) {
            if (group[i].attributes.med < lowest_med) lowest_med = group[i].attributes.med;
        }
        for (size_t i = 0; i < group.size(); i++) {
            if (group[i].attributes.med == lowest_med) result.push_back(group[i]);
        }
    }
    return result;
}

vector<RIBEntry> LocRIB::filter_by_peer_type(const vector<RIBEntry>& candidates) const {
    bool any_ebgp = false;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].peer_type == PeerType::EBGP) { any_ebgp = true; break; }
    }
    if (!any_ebgp) return candidates;

    vector<RIBEntry> result;
    for (size_t i = 0; i < candidates.size(); i++) {
        if (candidates[i].peer_type == PeerType::EBGP) result.push_back(candidates[i]);
    }
    return result;
}

RIBEntry LocRIB::select_best(const vector<RIBEntry>& candidates) const {
    RIBEntry winner;

    if (candidates.size() == 1) {
        winner = candidates[0];
        winner.is_best = true;
        winner.decisive_step = 0;
        winner.decisive_reason = "Only path";
        return winner;
    }

    vector<RIBEntry> remaining = filter_by_weight(candidates);
    if (remaining.size() == 1) {
        winner = remaining[0]; winner.is_best = true;
        winner.decisive_step = 1;
        winner.decisive_reason = "Highest weight (" + to_string(winner.weight) + ")";
        return winner;
    }

    remaining = filter_by_local_pref(remaining);
    if (remaining.size() == 1) {
        winner = remaining[0]; winner.is_best = true;
        winner.decisive_step = 2;
        winner.decisive_reason = "Highest LOCAL_PREF (" + to_string(winner.attributes.local_pref) + ")";
        return winner;
    }

    remaining = filter_by_locally_originated(remaining);
    if (remaining.size() == 1) {
        winner = remaining[0]; winner.is_best = true;
        winner.decisive_step = 3;
        winner.decisive_reason = "Locally originated";
        return winner;
    }

    remaining = filter_by_as_path_length(remaining);
    if (remaining.size() == 1) {
        winner = remaining[0]; winner.is_best = true;
        winner.decisive_step = 4;
        winner.decisive_reason = "Shortest AS_PATH (length " + to_string(winner.attributes.as_path.size()) + ")";
        return winner;
    }

    remaining = filter_by_origin(remaining);
    if (remaining.size() == 1) {
        winner = remaining[0]; winner.is_best = true;
        winner.decisive_step = 5;
        winner.decisive_reason = "Lowest origin type";
        return winner;
    }

    remaining = filter_by_med(remaining);
    if (remaining.size() == 1) {
        winner = remaining[0]; winner.is_best = true;
        winner.decisive_step = 6;
        winner.decisive_reason = "Lowest MED (" + to_string(winner.attributes.med) + ")";
        return winner;
    }

    remaining = filter_by_peer_type(remaining);
    if (remaining.size() == 1) {
        winner = remaining[0]; winner.is_best = true;
        winner.decisive_step = 7;
        winner.decisive_reason = "eBGP over iBGP";
        return winner;
    }

    winner = remaining[0];
    winner.is_best = true;
    winner.decisive_step = 7;
    winner.decisive_reason = "Tie after all steps";
    return winner;
}

void LocRIB::run_best_path_selection(const vector<AdjRIBIn>& adj_rib_ins) {
    routes.clear();

    map<string, vector<RIBEntry>> prefix_groups;

    for (size_t i = 0; i < adj_rib_ins.size(); i++) {
        vector<RIBEntry> peer_routes = adj_rib_ins[i].get_all_routes();
        for (size_t j = 0; j < peer_routes.size(); j++) {
            string key = prefix_to_key(peer_routes[j].prefix);
            prefix_groups[key].push_back(peer_routes[j]);
        }
    }

    for (auto it = prefix_groups.begin(); it != prefix_groups.end(); it++) {
        RIBEntry best = select_best(it->second);
        routes[it->first] = best;
    }
}

vector<RIBEntry> LocRIB::get_all_routes() const {
    vector<RIBEntry> result;
    for (auto it = routes.begin(); it != routes.end(); it++) {
        result.push_back(it->second);
    }
    return result;
}

int LocRIB::route_count() const {
    return routes.size();
}
