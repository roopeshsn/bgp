#include "prefix_analysis.h"
#include <algorithm>
#include <iostream>

using namespace std;


PrefixAnalyzer::PrefixAnalyzer()
    : route_count(0), total_as_path_entries(0), total_community_entries(0),
      as_path_table_memory(0), communities_table_memory(0) {
}

uint32_t PrefixAnalyzer::add_route(const Prefix& prefix, const PathAttributes& attributes) {
    route_count++;
    total_as_path_entries += attributes.as_path.size();
    total_community_entries += attributes.communities.size();

    // Per-attribute dedup tracking
    if (unique_as_path_set.find(attributes.as_path) == unique_as_path_set.end()) {
        unique_as_path_set.insert(attributes.as_path);
        as_path_table_memory += attributes.as_path.size() * sizeof(uint32_t)
                              + sizeof(vector<uint32_t>);
    }

    unique_next_hop_set.insert(attributes.next_hop);
    unique_local_pref_set.insert(attributes.local_pref);
    unique_med_set.insert(attributes.med);
    unique_origin_set.insert(attributes.origin);

    if (unique_communities_set.find(attributes.communities) == unique_communities_set.end()) {
        unique_communities_set.insert(attributes.communities);
        communities_table_memory += attributes.communities.size() * sizeof(uint32_t)
                                  + sizeof(vector<uint32_t>);
    }

    unique_aggregator_as_set.insert(attributes.aggregator_as);
    unique_aggregator_ip_set.insert(attributes.aggregator_ip);

    // Combined dedup
    auto it = attr_index_map.find(attributes);
    if (it != attr_index_map.end()) {
        attribute_table[it->second].ref_count++;
        return it->second;
    }

    uint32_t index = attribute_table.size();
    SharedAttributes shared;
    shared.attributes = attributes;
    shared.ref_count = 1;
    attribute_table.push_back(shared);
    attr_index_map[attributes] = index;

    return index;
}

const SharedAttributes& PrefixAnalyzer::get_attributes(uint32_t index) const {
    return attribute_table[index];
}

int PrefixAnalyzer::total_routes() const {
    return route_count;
}

int PrefixAnalyzer::unique_attribute_sets() const {
    return attribute_table.size();
}

int PrefixAnalyzer::unique_as_paths() const {
    return unique_as_path_set.size();
}

size_t PrefixAnalyzer::naive_memory_per_route() const {
    size_t fixed = sizeof(uint32_t)    // network
                 + sizeof(uint8_t)     // prefix length
                 + sizeof(Origin)      // origin
                 + sizeof(uint32_t)    // next_hop
                 + sizeof(uint32_t)    // local_pref
                 + sizeof(uint32_t)    // med
                 + sizeof(bool)        // atomic_aggregate
                 + sizeof(uint32_t)    // aggregator_as
                 + sizeof(uint32_t);   // aggregator_ip

    double avg_as_path_entries = 0;
    double avg_community_entries = 0;
    if (route_count > 0) {
        avg_as_path_entries = (double)total_as_path_entries / route_count;
        avg_community_entries = (double)total_community_entries / route_count;
    }

    size_t variable = (size_t)(avg_as_path_entries * sizeof(uint32_t))
                    + (size_t)(avg_community_entries * sizeof(uint32_t))
                    + 2 * sizeof(vector<uint32_t>);

    return fixed + variable;
}

size_t PrefixAnalyzer::naive_total_memory() const {
    return naive_memory_per_route() * route_count;
}

size_t PrefixAnalyzer::combined_dedup_memory() const {
    size_t total = 0;

    for (int i = 0; i < attribute_table.size(); i++) {
        const PathAttributes& attrs = attribute_table[i].attributes;

        size_t entry_size = sizeof(Origin)
                          + sizeof(uint32_t)    // next_hop
                          + sizeof(uint32_t)    // local_pref
                          + sizeof(uint32_t)    // med
                          + sizeof(bool)        // atomic_aggregate
                          + sizeof(uint32_t)    // aggregator_as
                          + sizeof(uint32_t)    // aggregator_ip
                          + sizeof(uint32_t)    // ref_count
                          + sizeof(vector<uint32_t>) * 2
                          + attrs.as_path.size() * sizeof(uint32_t)
                          + attrs.communities.size() * sizeof(uint32_t);

        total += entry_size;
    }

    // Per-route overhead: one index (uint32_t) per route to reference the table
    total += (size_t)route_count * sizeof(uint32_t);

    return total;
}

double PrefixAnalyzer::combined_dedup_ratio() const {
    if (attribute_table.size() == 0) return 0;
    return (double)route_count / attribute_table.size();
}

size_t PrefixAnalyzer::per_route_index_overhead() const {
    // Each route stores one index (uint32_t) per attribute table
    // origin + as_path + next_hop + local_pref + med + communities + aggregator_as + aggregator_ip
    return 8 * sizeof(uint32_t);
}

size_t PrefixAnalyzer::per_attribute_dedup_memory() const {
    size_t total = 0;

    // Origin table: just the enum values
    total += unique_origin_set.size() * sizeof(Origin);

    // AS_PATH table: variable-length vectors
    total += as_path_table_memory;

    // Next hop table: uint32_t per unique value
    total += unique_next_hop_set.size() * sizeof(uint32_t);

    // LOCAL_PREF table: uint32_t per unique value
    total += unique_local_pref_set.size() * sizeof(uint32_t);

    // MED table: uint32_t per unique value
    total += unique_med_set.size() * sizeof(uint32_t);

    // Communities table: variable-length vectors
    total += communities_table_memory;

    // Aggregator AS table
    total += unique_aggregator_as_set.size() * sizeof(uint32_t);

    // Aggregator IP table
    total += unique_aggregator_ip_set.size() * sizeof(uint32_t);

    // Per-route overhead: 8 indices to reference each attribute table
    total += (size_t)route_count * per_route_index_overhead();

    return total;
}

vector<PerAttributeStats> PrefixAnalyzer::per_attribute_stats() const {
    vector<PerAttributeStats> stats;

    stats.push_back({
        (int)unique_origin_set.size(),
        unique_origin_set.size() * sizeof(Origin),
        "ORIGIN"
    });

    stats.push_back({
        (int)unique_as_path_set.size(),
        as_path_table_memory,
        "AS_PATH"
    });

    stats.push_back({
        (int)unique_next_hop_set.size(),
        unique_next_hop_set.size() * sizeof(uint32_t),
        "NEXT_HOP"
    });

    stats.push_back({
        (int)unique_local_pref_set.size(),
        unique_local_pref_set.size() * sizeof(uint32_t),
        "LOCAL_PREF"
    });

    stats.push_back({
        (int)unique_med_set.size(),
        unique_med_set.size() * sizeof(uint32_t),
        "MED"
    });

    stats.push_back({
        (int)unique_communities_set.size(),
        communities_table_memory,
        "COMMUNITIES"
    });

    stats.push_back({
        (int)unique_aggregator_as_set.size(),
        unique_aggregator_as_set.size() * sizeof(uint32_t),
        "AGGREGATOR_AS"
    });

    stats.push_back({
        (int)unique_aggregator_ip_set.size(),
        unique_aggregator_ip_set.size() * sizeof(uint32_t),
        "AGGREGATOR_IP"
    });

    return stats;
}


vector<pair<uint32_t, const SharedAttributes*>> PrefixAnalyzer::top_shared(int n) const {
    vector<pair<uint32_t, const SharedAttributes*>> all;

    for (int i = 0; i < attribute_table.size(); i++) {
        all.push_back({attribute_table[i].ref_count, &attribute_table[i]});
    }

    sort(all.begin(), all.end(), [](const auto& a, const auto& b) {
        return a.first > b.first;
    });

    if ((int)all.size() > n) {
        all.resize(n);
    }

    return all;
}

map<int, int> PrefixAnalyzer::as_path_length_distribution() const {
    map<int, int> distribution;

    for (int i = 0; i < attribute_table.size(); i++) {
        int path_length = attribute_table[i].attributes.as_path.size();
        int count = attribute_table[i].ref_count;

        if (path_length >= 7) {
            distribution[7] += count;
        } else {
            distribution[path_length] += count;
        }
    }

    return distribution;
}

map<Origin, int> PrefixAnalyzer::origin_distribution() const {
    map<Origin, int> distribution;

    for (int i = 0; i < attribute_table.size(); i++) {
        Origin origin = attribute_table[i].attributes.origin;
        int count = attribute_table[i].ref_count;
        distribution[origin] += count;
    }

    return distribution;
}


// ---------------------------------------------------------------
// Best path selection
// ---------------------------------------------------------------

uint32_t PrefixAnalyzer::get_attr_index(const PathAttributes& attributes) const {
    auto it = attr_index_map.find(attributes);
    if (it != attr_index_map.end()) {
        return it->second;
    }
    return (uint32_t)-1;
}

void PrefixAnalyzer::free_per_attribute_sets() {
    unique_as_path_set.clear();
    unique_next_hop_set.clear();
    unique_local_pref_set.clear();
    unique_med_set.clear();
    unique_origin_set.clear();
    unique_communities_set.clear();
    unique_aggregator_as_set.clear();
    unique_aggregator_ip_set.clear();
}

void PrefixAnalyzer::set_peer_table(const vector<PeerEntry>& peer_table) {
    peers = peer_table;
}

void PrefixAnalyzer::add_route_to_group(const Prefix& prefix, uint32_t attr_index, uint16_t peer_index) {
    uint64_t key = ((uint64_t)prefix.network << 8) | prefix.length;
    prefix_groups[key].push_back({attr_index, peer_index});
}

vector<PrefixAnalyzer::RouteEntry> PrefixAnalyzer::filter_by_local_pref(const vector<RouteEntry>& candidates) const {
    uint32_t highest = 0;
    for (int i = 0; i < candidates.size(); i++) {
        uint32_t lp = attribute_table[candidates[i].attr_index].attributes.local_pref;
        if (lp > highest) {
            highest = lp;
        }
    }

    vector<RouteEntry> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (attribute_table[candidates[i].attr_index].attributes.local_pref == highest) {
            result.push_back(candidates[i]);
        }
    }
    return result;
}

vector<PrefixAnalyzer::RouteEntry> PrefixAnalyzer::filter_by_as_path_length(const vector<RouteEntry>& candidates) const {
    size_t shortest = attribute_table[candidates[0].attr_index].attributes.as_path.size();
    for (int i = 1; i < candidates.size(); i++) {
        size_t len = attribute_table[candidates[i].attr_index].attributes.as_path.size();
        if (len < shortest) {
            shortest = len;
        }
    }

    vector<RouteEntry> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (attribute_table[candidates[i].attr_index].attributes.as_path.size() == shortest) {
            result.push_back(candidates[i]);
        }
    }
    return result;
}

vector<PrefixAnalyzer::RouteEntry> PrefixAnalyzer::filter_by_origin(const vector<RouteEntry>& candidates) const {
    int lowest = static_cast<int>(attribute_table[candidates[0].attr_index].attributes.origin);
    for (int i = 1; i < candidates.size(); i++) {
        int val = static_cast<int>(attribute_table[candidates[i].attr_index].attributes.origin);
        if (val < lowest) {
            lowest = val;
        }
    }

    vector<RouteEntry> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (static_cast<int>(attribute_table[candidates[i].attr_index].attributes.origin) == lowest) {
            result.push_back(candidates[i]);
        }
    }
    return result;
}

vector<PrefixAnalyzer::RouteEntry> PrefixAnalyzer::filter_by_med(const vector<RouteEntry>& candidates) const {
    uint32_t lowest = attribute_table[candidates[0].attr_index].attributes.med;
    for (int i = 1; i < candidates.size(); i++) {
        uint32_t m = attribute_table[candidates[i].attr_index].attributes.med;
        if (m < lowest) {
            lowest = m;
        }
    }

    vector<RouteEntry> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (attribute_table[candidates[i].attr_index].attributes.med == lowest) {
            result.push_back(candidates[i]);
        }
    }
    return result;
}

vector<PrefixAnalyzer::RouteEntry> PrefixAnalyzer::filter_by_router_id(const vector<RouteEntry>& candidates) const {
    uint32_t lowest = peers[candidates[0].peer_index].peer_bgp_id;
    for (int i = 1; i < candidates.size(); i++) {
        uint32_t rid = peers[candidates[i].peer_index].peer_bgp_id;
        if (rid < lowest) {
            lowest = rid;
        }
    }

    vector<RouteEntry> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (peers[candidates[i].peer_index].peer_bgp_id == lowest) {
            result.push_back(candidates[i]);
        }
    }
    return result;
}

vector<PrefixAnalyzer::RouteEntry> PrefixAnalyzer::filter_by_peer_ip(const vector<RouteEntry>& candidates) const {
    uint32_t lowest = peers[candidates[0].peer_index].peer_ip;
    for (int i = 1; i < candidates.size(); i++) {
        uint32_t pip = peers[candidates[i].peer_index].peer_ip;
        if (pip < lowest) {
            lowest = pip;
        }
    }

    vector<RouteEntry> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (peers[candidates[i].peer_index].peer_ip == lowest) {
            result.push_back(candidates[i]);
        }
    }
    return result;
}

BestPathResult PrefixAnalyzer::select_best(const vector<RouteEntry>& candidates) const {
    BestPathResult result;
    result.candidate_count = candidates.size();

    if (candidates.size() == 1) {
        result.best = attribute_table[candidates[0].attr_index].attributes;
        result.decisive_step = 0;
        result.decisive_reason = "Only path";
        return result;
    }

    // Step 1: Highest LOCAL_PREF
    vector<RouteEntry> remaining = filter_by_local_pref(candidates);
    if (remaining.size() == 1) {
        result.best = attribute_table[remaining[0].attr_index].attributes;
        result.decisive_step = 1;
        result.decisive_reason = "Highest LOCAL_PREF";
        return result;
    }

    // Step 2: Shortest AS_PATH
    remaining = filter_by_as_path_length(remaining);
    if (remaining.size() == 1) {
        result.best = attribute_table[remaining[0].attr_index].attributes;
        result.decisive_step = 2;
        result.decisive_reason = "Shortest AS_PATH";
        return result;
    }

    // Step 3: Lowest Origin (IGP < EGP < INCOMPLETE)
    remaining = filter_by_origin(remaining);
    if (remaining.size() == 1) {
        result.best = attribute_table[remaining[0].attr_index].attributes;
        result.decisive_step = 3;
        result.decisive_reason = "Lowest ORIGIN";
        return result;
    }

    // Step 4: Lowest MED
    remaining = filter_by_med(remaining);
    if (remaining.size() == 1) {
        result.best = attribute_table[remaining[0].attr_index].attributes;
        result.decisive_step = 4;
        result.decisive_reason = "Lowest MED";
        return result;
    }

    // Step 5: Lowest Router ID
    remaining = filter_by_router_id(remaining);
    if (remaining.size() == 1) {
        result.best = attribute_table[remaining[0].attr_index].attributes;
        result.decisive_step = 5;
        result.decisive_reason = "Lowest Router ID";
        return result;
    }

    // Step 6: Lowest Peer IP
    remaining = filter_by_peer_ip(remaining);
    result.best = attribute_table[remaining[0].attr_index].attributes;
    result.decisive_step = 6;
    result.decisive_reason = "Lowest Peer IP";
    return result;
}

void PrefixAnalyzer::run_best_path_selection() {
    step_counts.clear();
    best_path_results.clear();

    int processed = 0;

    for (auto it = prefix_groups.begin(); it != prefix_groups.end(); it++) {
        BestPathResult result = select_best(it->second);
        best_path_results.push_back(result);
        step_counts[result.decisive_step]++;

        processed++;
        if (processed % 100000 == 0) {
            cout << "  Processed " << processed << " prefixes..." << endl;
        }
    }

    cout << "  Best path selection complete: " << processed << " prefixes" << endl;
}

vector<BestPathStepStats> PrefixAnalyzer::best_path_step_distribution() const {
    vector<BestPathStepStats> stats;

    string step_names[] = {
        "Only path",
        "LOCAL_PREF",
        "AS_PATH length",
        "ORIGIN",
        "MED",
        "Lowest Router ID",
        "Lowest Peer IP"
    };

    for (int step = 0; step <= 6; step++) {
        auto it = step_counts.find(step);
        int count = (it != step_counts.end()) ? it->second : 0;
        if (count > 0) {
            stats.push_back({step, step_names[step], count});
        }
    }

    return stats;
}

int PrefixAnalyzer::total_prefix_groups() const {
    return prefix_groups.size();
}

int PrefixAnalyzer::prefixes_with_multiple_paths() const {
    int count = 0;
    for (auto it = prefix_groups.begin(); it != prefix_groups.end(); it++) {
        if (it->second.size() > 1) {
            count++;
        }
    }
    return count;
}

vector<PrefixAnalyzer::PrefixPathCount> PrefixAnalyzer::top_prefixes_by_path_count(int n) const {
    vector<PrefixPathCount> all;

    for (auto it = prefix_groups.begin(); it != prefix_groups.end(); it++) {
        Prefix p;
        p.network = (uint32_t)(it->first >> 8);
        p.length = (uint8_t)(it->first & 0xFF);
        all.push_back({p, (int)it->second.size()});
    }

    sort(all.begin(), all.end(), [](const PrefixPathCount& a, const PrefixPathCount& b) {
        return a.path_count > b.path_count;
    });

    if ((int)all.size() > n) {
        all.resize(n);
    }

    return all;
}
