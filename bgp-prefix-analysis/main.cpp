// BGP Prefix Analysis with Patricia Trie and Attribute Deduplication
//
// Parses a real MRT RIB dump file and analyzes prefix storage efficiency.
//
// Download a RIB dump file:
//   RIPE RIS:
//     curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz
//
//   RouteViews (decompress bz2 first, then gzip):
//     curl -O http://archive.routeviews.org/bgpdata/2025.06/RIBS/rib.20250601.0000.bz2
//     bunzip2 rib.20250601.0000.bz2
//     gzip rib.20250601.0000
//
// Build:
//   g++ -std=c++17 -lz -o bgp_prefix_analysis main.cpp mrt_parser.cpp compressed_trie.cpp prefix_analysis.cpp
//
// Run:
//   ./bgp_prefix_analysis latest-bview.gz

#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>
#include "bgp_types.h"
#include "mrt_parser.h"
#include "compressed_trie.h"
#include "prefix_analysis.h"

using namespace std;


string ip_to_string(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "."
         + to_string((ip >> 16) & 0xFF) + "."
         + to_string((ip >> 8) & 0xFF) + "."
         + to_string(ip & 0xFF);
}

string prefix_to_string(const Prefix& prefix) {
    return ip_to_string(prefix.network) + "/" + to_string(prefix.length);
}

string origin_to_string(Origin origin) {
    switch (origin) {
        case Origin::IGP:        return "IGP";
        case Origin::EGP:        return "EGP";
        case Origin::INCOMPLETE: return "INCOMPLETE";
    }
    return "?";
}

string as_path_to_string(const vector<uint32_t>& as_path) {
    string result = "";
    for (int i = 0; i < as_path.size(); i++) {
        if (i > 0) result += " ";
        result += to_string(as_path[i]);
    }
    return result;
}

string format_bytes(size_t bytes) {
    if (bytes >= 1024 * 1024 * 1024) {
        double gb = (double)bytes / (1024 * 1024 * 1024);
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f GB", gb);
        return string(buf);
    } else if (bytes >= 1024 * 1024) {
        double mb = (double)bytes / (1024 * 1024);
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f MB", mb);
        return string(buf);
    } else if (bytes >= 1024) {
        double kb = (double)bytes / 1024;
        char buf[32];
        snprintf(buf, sizeof(buf), "%.1f KB", kb);
        return string(buf);
    }
    return to_string(bytes) + " B";
}

string format_number(int n) {
    string s = to_string(n);
    string result = "";

    int count = 0;
    for (int i = s.size() - 1; i >= 0; i--) {
        if (count > 0 && count % 3 == 0) {
            result = "," + result;
        }
        result = s[i] + result;
        count++;
    }

    return result;
}


void print_usage() {
    cout << "Usage: bgp_prefix_analysis <rib_dump.gz>" << endl;
    cout << endl;
    cout << "Download a RIB dump:" << endl;
    cout << "  curl -O https://data.ris.ripe.net/rrc00/latest-bview.gz" << endl;
    cout << endl;
    cout << "Then run:" << endl;
    cout << "  ./bgp_prefix_analysis latest-bview.gz" << endl;
}


int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);

    if (argc < 2) {
        print_usage();
        return 1;
    }

    string filename = argv[1];

    cout << "=== BGP Prefix Analysis ===" << endl;
    cout << "Source: " << filename << endl;
    cout << endl;


    // ---------------------------------------------------------------
    // Step 1: Parse MRT RIB dump
    // ---------------------------------------------------------------

    cout << "--- Step 1: Parse MRT RIB dump ---" << endl;

    MrtParser parser;
    if (!parser.open(filename)) {
        cout << "ERROR: Failed to open " << filename << endl;
        return 1;
    }

    CompressedTrie trie;
    PrefixAnalyzer analyzer;

    auto start_time = chrono::steady_clock::now();

    parser.parse_rib_dump([&](const Prefix& prefix, const PathAttributes& attrs, uint16_t peer_index) {
        uint32_t attr_index = analyzer.add_route(prefix, attrs);
        trie.insert(prefix, attr_index);
    });

    parser.close();

    auto end_time = chrono::steady_clock::now();
    double elapsed = chrono::duration<double>(end_time - start_time).count();

    cout << "  Time: " << fixed << setprecision(1) << elapsed << " seconds" << endl;
    cout << endl;


    // ---------------------------------------------------------------
    // Step 2: Patricia trie stats
    // ---------------------------------------------------------------

    cout << "--- Step 2: Trie stats (plain vs compressed) ---" << endl;
    cout << endl;

    int compressed_nodes = trie.node_count();
    int total_prefixes = trie.prefix_count();
    int plain_nodes = trie.plain_trie_node_count();

    cout << "  Plain binary trie (one node per bit):" << endl;
    cout << "    Nodes:             " << format_number(plain_nodes) << endl;
    cout << "    Memory:            " << format_bytes(trie.plain_trie_memory()) << endl;
    cout << endl;

    cout << "  Compressed trie (path compression):" << endl;
    cout << "    Nodes:             " << format_number(compressed_nodes) << endl;
    cout << "    Memory:            " << format_bytes(trie.memory_usage()) << endl;
    cout << endl;

    double node_reduction = (plain_nodes > 0) ? (double)plain_nodes / compressed_nodes : 0;
    double mem_reduction = (trie.plain_trie_memory() > 0) ?
        (double)trie.plain_trie_memory() / trie.memory_usage() : 0;

    cout << "  Prefixes stored:     " << format_number(total_prefixes) << endl;
    cout << "  Max depth:           " << trie.max_depth() << endl;
    cout << "  Node reduction:      " << fixed << setprecision(1) << node_reduction << "x" << endl;
    cout << "  Memory reduction:    " << fixed << setprecision(1) << mem_reduction << "x" << endl;
    cout << endl;


    // ---------------------------------------------------------------
    // Step 3: Attribute deduplication
    // ---------------------------------------------------------------

    cout << "--- Step 3: Attribute deduplication ---" << endl;

    cout << "  Total route entries:           " << format_number(analyzer.total_routes()) << endl;
    cout << "  Unique attribute combinations: " << format_number(analyzer.unique_attribute_sets()) << endl;
    cout << "  Unique AS paths:               " << format_number(analyzer.unique_as_paths()) << endl;
    cout << "  Combined dedup ratio:          " << fixed << setprecision(1)
         << analyzer.combined_dedup_ratio() << "x" << endl;
    cout << endl;


    // ---------------------------------------------------------------
    // Step 4: Per-attribute deduplication
    // ---------------------------------------------------------------

    cout << "--- Step 4: Per-attribute deduplication ---" << endl;
    cout << endl;

    cout << "  " << left << setw(18) << "Attribute"
         << right << setw(12) << "Unique"
         << right << setw(14) << "Table Size"
         << right << setw(14) << "Dedup Ratio" << endl;

    cout << "  " << left << setw(18) << "---------"
         << right << setw(12) << "------"
         << right << setw(14) << "----------"
         << right << setw(14) << "-----------" << endl;

    auto per_attr = analyzer.per_attribute_stats();
    for (int i = 0; i < per_attr.size(); i++) {
        double ratio = (analyzer.total_routes() > 0) ?
            (double)analyzer.total_routes() / per_attr[i].unique_count : 0;

        cout << "  " << left << setw(18) << per_attr[i].name
             << right << setw(12) << format_number(per_attr[i].unique_count)
             << right << setw(14) << format_bytes(per_attr[i].total_memory)
             << right << setw(12) << fixed << setprecision(1) << ratio << "x" << endl;
    }
    cout << endl;


    // ---------------------------------------------------------------
    // Step 5: Distributions
    // ---------------------------------------------------------------

    cout << "--- Step 5: Distributions ---" << endl;
    cout << endl;

    // Origin type distribution
    cout << "  Origin type:" << endl;
    map<Origin, int> origin_dist = analyzer.origin_distribution();
    int total = analyzer.total_routes();
    for (auto it = origin_dist.begin(); it != origin_dist.end(); it++) {
        double pct = (total > 0) ? (double)it->second / total * 100 : 0;
        cout << "    " << left << setw(14) << origin_to_string(it->first)
             << right << setw(10) << format_number(it->second)
             << "  (" << fixed << setprecision(1) << pct << "%)" << endl;
    }
    cout << endl;

    // AS path length distribution
    cout << "  AS path length:" << endl;
    map<int, int> as_dist = analyzer.as_path_length_distribution();
    for (auto it = as_dist.begin(); it != as_dist.end(); it++) {
        double pct = (total > 0) ? (double)it->second / total * 100 : 0;
        string label = (it->first >= 7) ? "7+" : to_string(it->first);
        cout << "    Length " << left << setw(6) << label
             << right << setw(10) << format_number(it->second)
             << "  (" << fixed << setprecision(1) << pct << "%)" << endl;
    }
    cout << endl;

    // Prefix length distribution (by subnet mask)
    cout << "  Prefix length (subnet mask):" << endl;
    map<int, int> prefix_len_dist = trie.prefix_length_distribution();
    int total_prefixes_dist = trie.prefix_count();
    for (int len = 0; len <= 32; len++) {
        int count = 0;
        auto it = prefix_len_dist.find(len);
        if (it != prefix_len_dist.end()) {
            count = it->second;
        }
        double pct = (total_prefixes_dist > 0) ?
            (double)count / total_prefixes_dist * 100 : 0;
        cout << "    /" << left << setw(10) << len
             << right << setw(10) << format_number(count)
             << "  (" << fixed << setprecision(1) << pct << "%)" << endl;
    }
    cout << endl;


    // ---------------------------------------------------------------
    // Step 6: Best path selection
    // ---------------------------------------------------------------

    cout << "--- Step 6: Best path selection ---" << endl;
    cout << endl;

    analyzer.free_per_attribute_sets();

    // Second pass: build prefix groups for best path selection
    cout << "  Parsing routes for best path grouping..." << endl;

    MrtParser parser2;
    parser2.open(filename);
    parser2.parse_rib_dump([&](const Prefix& prefix, const PathAttributes& attrs, uint16_t peer_index) {
        uint32_t attr_index = analyzer.get_attr_index(attrs);
        if (attr_index != (uint32_t)-1) {
            analyzer.add_route_to_group(prefix, attr_index, peer_index);
        }
    });
    parser2.close();

    analyzer.set_peer_table(parser2.get_peer_table());

    auto bp_start = chrono::steady_clock::now();
    analyzer.run_best_path_selection();
    auto bp_end = chrono::steady_clock::now();
    double bp_elapsed = chrono::duration<double>(bp_end - bp_start).count();

    int total_prefixes_bp = analyzer.total_routes();
    int multi_path = analyzer.prefixes_with_multiple_paths();

    cout << endl;
    cout << "  Total prefixes:              " << format_number(analyzer.total_prefix_groups()) << endl;
    cout << "  Prefixes with multiple paths: " << format_number(multi_path) << endl;
    cout << "  Time: " << fixed << setprecision(1) << bp_elapsed << " seconds" << endl;
    cout << endl;

    cout << "  Decisive step distribution:" << endl;
    cout << endl;

    cout << "  " << left << setw(6) << "Step"
         << left << setw(24) << "Decisive Factor"
         << right << setw(12) << "Prefixes"
         << right << setw(10) << "%" << endl;

    cout << "  " << left << setw(6) << "----"
         << left << setw(24) << "----------------"
         << right << setw(12) << "--------"
         << right << setw(10) << "--" << endl;

    auto step_dist = analyzer.best_path_step_distribution();
    int total_decided = 0;
    for (int i = 0; i < step_dist.size(); i++) {
        total_decided += step_dist[i].count;
    }

    for (int i = 0; i < step_dist.size(); i++) {
        double pct = (total_decided > 0) ?
            (double)step_dist[i].count / total_decided * 100 : 0;

        cout << "  " << left << setw(6) << step_dist[i].step
             << left << setw(24) << step_dist[i].name
             << right << setw(12) << format_number(step_dist[i].count)
             << right << setw(9) << fixed << setprecision(1) << pct << "%" << endl;
    }
    cout << endl;

    cout << "  Top 10 prefixes by path count:" << endl;
    cout << endl;

    cout << "  " << left << setw(6) << "Rank"
         << left << setw(22) << "Prefix"
         << right << setw(10) << "Paths" << endl;

    cout << "  " << left << setw(6) << "----"
         << left << setw(22) << "------"
         << right << setw(10) << "-----" << endl;

    auto top_prefixes = analyzer.top_prefixes_by_path_count(10);
    for (int i = 0; i < top_prefixes.size(); i++) {
        cout << "  " << left << setw(6) << (i + 1)
             << left << setw(22) << prefix_to_string(top_prefixes[i].prefix)
             << right << setw(10) << format_number(top_prefixes[i].path_count) << endl;
    }
    cout << endl;

    return 0;
}
