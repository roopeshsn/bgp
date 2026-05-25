#include <iostream>
#include <iomanip>
#include <vector>
#include "bgp_types.h"
#include "best_path.h"

using namespace std;

// Arista EOS origin codes: i = IGP, e = EGP, ? = incomplete
char origin_code(Origin origin) {
    switch (origin) {
        case Origin::IGP:        return 'i';
        case Origin::EGP:        return 'e';
        case Origin::INCOMPLETE: return '?';
    }
    return '?';
}

string origin_to_string(Origin origin) {
    switch (origin) {
        case Origin::IGP:        return "IGP";
        case Origin::EGP:        return "EGP";
        case Origin::INCOMPLETE: return "Incomplete";
    }
    return "Unknown";
}

string peer_type_label(PeerType type) {
    switch (type) {
        case PeerType::EBGP: return "external";
        case PeerType::IBGP: return "internal";
    }
    return "unknown";
}

string as_path_to_string(const vector<uint32_t>& as_path) {
    string result = "";
    for (int i = 0; i < as_path.size(); i++) {
        if (i > 0) {
            result += " ";
        }
        result += to_string(as_path[i]);
    }
    return result;
}

string prefix_to_string(const Prefix& prefix) {
    return prefix.network + "/" + to_string(prefix.length);
}


// Print the Arista EOS-style header that appears at the top of "show ip bgp"
void print_eos_header(uint32_t local_as, const string& router_id) {
    cout << "BGP routing table information for VRF default\n";
    cout << "Router identifier " << router_id
         << ", local AS number " << local_as << "\n";
    cout << "Route status codes: s - suppressed, * - valid, > - active,\n";
    cout << "                    S - Stale, b - backup\n";
    cout << "Origin codes: i - IGP, e - EGP, ? - incomplete\n";
    cout << "\n";
}

// Print the column headers for the table view
void print_eos_table_header() {
    cout << "          Network                Next Hop              Metric  LocPrf  Weight  Path\n";
}

// Build the status flags string for a route.
// Format matches Arista EOS positional flags:
//   position 0: ' ' (space, no suppression/damping)
//   position 1: '*' if valid
//   position 2: '>' if best, 'b' if backup, ' ' otherwise
//   position 3: 'i' if iBGP, ' ' if eBGP
string build_status_flags(bool is_best, bool is_backup, PeerType peer_type) {
    string flags = " ";
    flags += '*';
    if (is_best) {
        flags += '>';
    } else if (is_backup) {
        flags += 'b';
    } else {
        flags += ' ';
    }
    if (peer_type == PeerType::IBGP) {
        flags += 'i';
    } else {
        flags += ' ';
    }
    return flags;
}

// Print a single route in EOS table format
void print_eos_table_row(const CandidatePath& candidate, bool is_best, bool is_backup,
                         bool show_network) {
    string flags = build_status_flags(is_best, is_backup, candidate.peer_type);
    cout << flags << "    ";

    // Network column — only shown on first row for a prefix group
    string network_str = "";
    if (show_network) {
        network_str = prefix_to_string(candidate.prefix);
    }
    cout << left << setw(22) << network_str;

    // Next Hop
    cout << left << setw(22) << candidate.attributes.next_hop;

    // Metric (MED)
    cout << right << setw(6) << candidate.attributes.med;

    // LocPrf
    cout << right << setw(8) << candidate.attributes.local_pref;

    // Weight
    cout << right << setw(8) << candidate.weight;

    // AS Path + Origin code
    cout << "    " << as_path_to_string(candidate.attributes.as_path)
         << " " << origin_code(candidate.attributes.origin);

    cout << "\n";
}


// Print the detailed per-prefix view (like "show ip bgp <prefix>" on Arista EOS).
// Shows all candidate paths with their attributes and labels which is
// best, backup, or just valid.
void print_eos_detailed(const vector<CandidatePath>& candidates,
                        const BackupSelectionResult& result) {
    string prefix_str = prefix_to_string(candidates[0].prefix);
    cout << "BGP routing table entry for " << prefix_str << "\n";
    cout << " Paths: " << candidates.size() << " available\n";

    for (int i = 0; i < candidates.size(); i++) {
        bool is_best = (candidates[i].peer_ip == result.best.best.peer_ip);
        bool is_backup = result.has_backup
                         && (candidates[i].peer_ip == result.backup.best.peer_ip);

        // AS Path line
        cout << "  " << as_path_to_string(candidates[i].attributes.as_path) << "\n";

        // Next hop line
        cout << "    " << candidates[i].attributes.next_hop
             << " from " << candidates[i].peer_ip
             << " (AS " << candidates[i].neighbor_as << ")\n";

        // Attributes line
        cout << "      Origin " << origin_to_string(candidates[i].attributes.origin)
             << ", metric " << candidates[i].attributes.med
             << ", localpref " << candidates[i].attributes.local_pref
             << ", weight " << candidates[i].weight
             << ", valid, " << peer_type_label(candidates[i].peer_type);

        if (is_best) {
            cout << ", best";
        }
        if (is_backup) {
            cout << ", backup";
        }
        cout << "\n";

        // Show which step decided (for best and backup)
        if (is_best) {
            cout << "      Decided by step " << result.best.decisive_step
                 << ": " << result.best.decisive_reason << "\n";
        }
        if (is_backup) {
            cout << "      Decided by step " << result.backup.decisive_step
                 << ": " << result.backup.decisive_reason << "\n";
        }
    }
}


// Run a single scenario: show detailed EOS view, then the table view
void run_scenario(const string& title, const string& description,
                  const vector<CandidatePath>& candidates) {
    cout << "--- " << title << " ---\n";
    cout << description << "\n\n";

    BackupSelectionResult result = select_best_and_backup_path(candidates);

    // Detailed view (show ip bgp <prefix>)
    print_eos_detailed(candidates, result);
    cout << "\n";

    // Table view (show ip bgp)
    print_eos_table_header();

    for (int i = 0; i < candidates.size(); i++) {
        bool is_best = (candidates[i].peer_ip == result.best.best.peer_ip);
        bool is_backup = result.has_backup
                         && (candidates[i].peer_ip == result.backup.best.peer_ip);
        bool show_network = (i == 0);
        print_eos_table_row(candidates[i], is_best, is_backup, show_network);
    }

    cout << "\n\n";
}


int main() {
    uint32_t local_as = 65001;
    string router_id = "10.0.0.100";

    print_eos_header(local_as, router_id);

    // Scenario 1: LOCAL_PREF decides
    {
        vector<CandidatePath> candidates = {
            {
                {"172.16.0.0", 16},
                {Origin::IGP, {65001, 65002}, "10.0.0.1", 100, 0, false},
                0,
                PeerType::EBGP,
                65002,
                false,
                "10.0.0.1"
            },
            {
                {"172.16.0.0", 16},
                {Origin::IGP, {65001, 65003}, "10.0.0.2", 200, 0, false},
                0,
                PeerType::EBGP,
                65003,
                false,
                "10.0.0.2"
            },
            {
                {"172.16.0.0", 16},
                {Origin::IGP, {65001, 65004}, "10.0.0.3", 150, 0, false},
                0,
                PeerType::EBGP,
                65004,
                false,
                "10.0.0.3"
            }
        };

        run_scenario(
            "Scenario 1: LOCAL_PREF",
            "Three paths to 172.16.0.0/16 — highest LOCAL_PREF wins",
            candidates
        );
    }

    // Scenario 2: Locally originated route preferred
    {
        vector<CandidatePath> candidates = {
            {
                {"192.168.1.0", 24},
                {Origin::IGP, {65001, 65002}, "10.0.0.1", 100, 0, false},
                0,
                PeerType::EBGP,
                65002,
                false,
                "10.0.0.1"
            },
            {
                {"192.168.1.0", 24},
                {Origin::IGP, {65001}, "0.0.0.0", 100, 0, false},
                0,
                PeerType::EBGP,
                0,
                true,
                "local"
            }
        };

        run_scenario(
            "Scenario 2: Locally Originated",
            "Two paths to 192.168.1.0/24 — locally originated route preferred",
            candidates
        );
    }

    // Scenario 3: AS_PATH length decides
    {
        vector<CandidatePath> candidates = {
            {
                {"10.2.0.0", 16},
                {Origin::IGP, {65001, 65002, 65003, 65004}, "10.0.0.1", 100, 0, false},
                0,
                PeerType::EBGP,
                65002,
                false,
                "10.0.0.1"
            },
            {
                {"10.2.0.0", 16},
                {Origin::IGP, {65001, 65005}, "10.0.0.2", 100, 0, false},
                0,
                PeerType::EBGP,
                65005,
                false,
                "10.0.0.2"
            },
            {
                {"10.2.0.0", 16},
                {Origin::IGP, {65001, 65006, 65007}, "10.0.0.3", 100, 0, false},
                0,
                PeerType::EBGP,
                65006,
                false,
                "10.0.0.3"
            }
        };

        run_scenario(
            "Scenario 3: AS_PATH Length",
            "Three paths to 10.2.0.0/16 — shortest AS_PATH wins",
            candidates
        );
    }

    // Scenario 4: Backup path selection
    {
        vector<CandidatePath> candidates = {
            {
                {"10.6.0.0", 24},
                {Origin::IGP, {65001, 65002, 65010}, "10.0.0.1", 100, 0, false},
                0,
                PeerType::EBGP,
                65002,
                false,
                "10.0.0.1"
            },
            {
                {"10.6.0.0", 24},
                {Origin::IGP, {65001, 65003}, "10.0.0.2", 150, 0, false},
                0,
                PeerType::EBGP,
                65003,
                false,
                "10.0.0.2"
            },
            {
                {"10.6.0.0", 24},
                {Origin::IGP, {65001, 65004}, "10.0.0.3", 120, 0, false},
                0,
                PeerType::EBGP,
                65004,
                false,
                "10.0.0.3"
            },
            {
                {"10.6.0.0", 24},
                {Origin::IGP, {65001, 65005, 65006, 65007}, "10.0.0.4", 100, 0, false},
                0,
                PeerType::IBGP,
                65005,
                false,
                "10.0.0.4"
            }
        };

        run_scenario(
            "Scenario 4: Backup Path Selection",
            "Four paths to 10.6.0.0/24 — best and backup (second-best) selected",
            candidates
        );
    }

    return 0;
}
