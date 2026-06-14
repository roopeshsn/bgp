#ifndef PREFIX_ANALYSIS_H
#define PREFIX_ANALYSIS_H

#include "bgp_types.h"
#include "mrt_parser.h"
#include <vector>
#include <unordered_map>
#include <set>
#include <map>

using namespace std;


struct PerAttributeStats {
    int unique_count;
    size_t total_memory;
    string name;
};

struct BestPathResult {
    PathAttributes best;
    int decisive_step;
    string decisive_reason;
    int candidate_count;
};

struct BestPathStepStats {
    int step;
    string name;
    int count;
};

// Hash for vector<uint32_t> (used for AS_PATH and communities dedup)
struct VectorHash {
    size_t operator()(const vector<uint32_t>& v) const {
        size_t result = 0;
        for (uint32_t val : v) {
            result ^= hash<uint32_t>()(val) + 0x9e3779b9 + (result << 6) + (result >> 2);
        }
        return result;
    }
};


class PrefixAnalyzer {
public:
    PrefixAnalyzer();

    uint32_t add_route(const Prefix& prefix, const PathAttributes& attributes);

    const SharedAttributes& get_attributes(uint32_t index) const;

    int total_routes() const;
    int unique_attribute_sets() const;
    int unique_as_paths() const;

    size_t naive_memory_per_route() const;
    size_t naive_total_memory() const;

    // Combined dedup: one table for the full attribute set
    size_t combined_dedup_memory() const;
    double combined_dedup_ratio() const;

    // Per-attribute dedup: separate table for each attribute
    size_t per_attribute_dedup_memory() const;
    vector<PerAttributeStats> per_attribute_stats() const;
    size_t per_route_index_overhead() const;

    vector<pair<uint32_t, const SharedAttributes*>> top_shared(int n) const;

    map<int, int> as_path_length_distribution() const;
    map<Origin, int> origin_distribution() const;

    void free_per_attribute_sets();
    uint32_t get_attr_index(const PathAttributes& attributes) const;

    // Best path selection
    void set_peer_table(const vector<PeerEntry>& peers);
    void add_route_to_group(const Prefix& prefix, uint32_t attr_index, uint16_t peer_index);
    void run_best_path_selection();
    vector<BestPathStepStats> best_path_step_distribution() const;
    int prefixes_with_multiple_paths() const;
    int total_prefix_groups() const;

    struct PrefixPathCount {
        Prefix prefix;
        int path_count;
    };
    vector<PrefixPathCount> top_prefixes_by_path_count(int n) const;

private:
    struct RouteEntry {
        uint32_t attr_index;
        uint16_t peer_index;
    };

    // Best path selection filters
    vector<RouteEntry> filter_by_local_pref(const vector<RouteEntry>& candidates) const;
    vector<RouteEntry> filter_by_as_path_length(const vector<RouteEntry>& candidates) const;
    vector<RouteEntry> filter_by_origin(const vector<RouteEntry>& candidates) const;
    vector<RouteEntry> filter_by_med(const vector<RouteEntry>& candidates) const;
    vector<RouteEntry> filter_by_router_id(const vector<RouteEntry>& candidates) const;
    vector<RouteEntry> filter_by_peer_ip(const vector<RouteEntry>& candidates) const;
    BestPathResult select_best(const vector<RouteEntry>& candidates) const;

    // Peer table from MRT dump
    vector<PeerEntry> peers;

    // Route groups for best path selection
    map<uint64_t, vector<RouteEntry>> prefix_groups;
    vector<BestPathResult> best_path_results;
    map<int, int> step_counts;
    // Combined dedup table
    vector<SharedAttributes> attribute_table;
    unordered_map<PathAttributes, uint32_t, PathAttributesHash> attr_index_map;
    int route_count;

    size_t total_as_path_entries;
    size_t total_community_entries;

    // Per-attribute dedup tables
    set<vector<uint32_t>> unique_as_path_set;
    set<uint32_t> unique_next_hop_set;
    set<uint32_t> unique_local_pref_set;
    set<uint32_t> unique_med_set;
    set<Origin> unique_origin_set;
    set<vector<uint32_t>> unique_communities_set;
    set<uint32_t> unique_aggregator_as_set;
    set<uint32_t> unique_aggregator_ip_set;

    // Track total memory for variable-length per-attribute tables
    size_t as_path_table_memory;
    size_t communities_table_memory;
};

#endif
