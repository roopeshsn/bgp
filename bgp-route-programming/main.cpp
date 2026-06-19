// BGP Route Programming — Mini Zebra
//
// Programs routes from multiple routing protocols into the kernel
// routing table using platform-specific APIs.
//
// Pipeline: Protocol Routes → Central RIB (admin distance) → Kernel RIB
//
// Build:
//   g++ -std=c++17 -o bgp_route_programmer main.cpp central_rib.cpp route_programmer.cpp
//
// Run:
//   ./bgp_route_programmer           (dry-run without root)
//   sudo ./bgp_route_programmer      (programs real kernel routes)

#include <iostream>
#include <iomanip>
#include <csignal>
#include <vector>
#include "bgp_types.h"
#include "central_rib.h"
#include "route_programmer.h"

using namespace std;


// Tracks programmed routes for cleanup on SIGINT
RouteProgrammer* global_programmer = nullptr;
vector<Route> global_programmed_routes;

void signal_handler(int signal) {
    if (global_programmer && !global_programmed_routes.empty()) {
        cout << endl;
        cout << "  Caught SIGINT — cleaning up programmed routes..." << endl;

        for (auto& route : global_programmed_routes) {
            auto result = global_programmer->delete_route(route);
            cout << "  Deleting " << route.prefix.to_string()
                 << " ... " << (result.success ? "OK" : result.error) << endl;
        }

        global_programmer->close();
    }

    exit(0);
}


int main() {
    setbuf(stdout, NULL);

    signal(SIGINT, signal_handler);

    cout << "=== BGP Route Programming ===" << endl;
    cout << "Mini Zebra — Protocol Routes -> Central RIB -> Kernel RIB" << endl;
    cout << endl;


    // ---------------------------------------------------------------
    // Step 1: Define protocol routes
    // ---------------------------------------------------------------

    cout << "--- Step 1: Define protocol routes ---" << endl;
    cout << endl;

    vector<Route> protocol_routes = {
        // Connected routes (AD 0) — directly attached interfaces
        {{"10.0.0.0", 30}, "0.0.0.0", RouteProtocol::CONNECTED, 0, 0,
            "eth0 direct", RouteState::PENDING},
        {{"10.0.1.0", 30}, "0.0.0.0", RouteProtocol::CONNECTED, 0, 0,
            "eth1 direct", RouteState::PENDING},

        // Static routes (AD 1) — manually configured
        {{"10.1.0.0", 24}, "10.0.0.2", RouteProtocol::STATIC, 1, 0,
            "configured", RouteState::PENDING},
        {{"172.16.0.0", 16}, "10.0.0.2", RouteProtocol::STATIC, 1, 0,
            "configured", RouteState::PENDING},

        // OSPF routes (AD 110) — learned from OSPF neighbors
        {{"10.1.0.0", 24}, "10.0.0.3", RouteProtocol::OSPF, 110, 100,
            "area 0, cost 100", RouteState::PENDING},
        {{"10.2.0.0", 24}, "10.0.0.3", RouteProtocol::OSPF, 110, 200,
            "area 0, cost 200", RouteState::PENDING},
        {{"192.168.1.0", 24}, "10.0.0.3", RouteProtocol::OSPF, 110, 50,
            "area 1, cost 50", RouteState::PENDING},

        // BGP routes (AD 200) — learned from BGP peers
        {{"10.1.0.0", 24}, "10.0.0.4", RouteProtocol::BGP, 200, 0,
            "peer 10.0.0.4 AS65002", RouteState::PENDING},
        {{"172.16.0.0", 16}, "10.0.0.5", RouteProtocol::BGP, 200, 0,
            "peer 10.0.0.5 AS65003", RouteState::PENDING},
        {{"10.3.0.0", 24}, "10.0.0.4", RouteProtocol::BGP, 200, 0,
            "peer 10.0.0.4 AS65002", RouteState::PENDING},
    };

    cout << "  " << left << setw(12) << "Protocol"
         << setw(4) << "AD"
         << setw(20) << "Prefix"
         << setw(14) << "Next Hop"
         << "Source" << endl;

    cout << "  " << left << setw(12) << "--------"
         << setw(4) << "--"
         << setw(20) << "------"
         << setw(14) << "--------"
         << "------" << endl;

    for (auto& route : protocol_routes) {
        cout << "  " << left << setw(12) << CentralRIB::protocol_name(route.protocol)
             << right << setw(3) << (int)route.admin_distance << " "
             << left << setw(20) << route.prefix.to_string()
             << setw(14) << route.next_hop
             << route.source_info << endl;
    }

    cout << endl;
    cout << "  Total: " << protocol_routes.size() << " routes from "
         << "4 protocols" << endl;
    cout << endl;


    // ---------------------------------------------------------------
    // Step 2: Central RIB selection
    // ---------------------------------------------------------------

    cout << "--- Step 2: Central RIB selection (admin distance) ---" << endl;
    cout << endl;

    CentralRIB rib;

    for (auto& route : protocol_routes) {
        rib.add_route(route);
    }

    auto prefix_keys = rib.get_all_prefix_keys();
    auto best_routes = rib.get_best_routes();

    for (auto& key : prefix_keys) {
        cout << "  " << key << endl;

        // Find the best route for this prefix
        Route* best = nullptr;
        for (auto& br : best_routes) {
            if (br.prefix.to_string() == key) {
                best = &br;
                break;
            }
        }

        // Parse the prefix from the key to get candidates
        size_t slash = key.find('/');
        Prefix prefix;
        prefix.network = key.substr(0, slash);
        prefix.length = stoi(key.substr(slash + 1));

        auto candidates = rib.get_candidates(prefix);

        for (auto& candidate : candidates) {
            bool is_best = (best &&
                candidate.protocol == best->protocol &&
                candidate.next_hop == best->next_hop);

            cout << "    " << (is_best ? "> " : "  ")
                 << left << setw(12) << CentralRIB::protocol_name(candidate.protocol)
                 << right << setw(3) << (int)candidate.admin_distance << "     "
                 << left << setw(16) << candidate.next_hop
                 << candidate.source_info << endl;
        }

        cout << endl;
    }

    cout << "  Best routes selected: " << best_routes.size() << " (from "
         << protocol_routes.size() << " candidates)" << endl;
    cout << endl;


    // ---------------------------------------------------------------
    // Step 3: Open routing socket
    // ---------------------------------------------------------------

    cout << "--- Step 3: Open routing socket ---" << endl;
    cout << endl;

    RouteProgrammer programmer;
    global_programmer = &programmer;

    if (!programmer.open()) {
        cout << "  ERROR: Failed to open routing socket" << endl;
        return 1;
    }

    cout << "  Platform: " << RouteProgrammer::platform_name() << endl;

    if (programmer.is_dry_run()) {
        cout << "  Mode:     DRY-RUN (run with sudo to program real routes)" << endl;
    } else {
        cout << "  Mode:     LIVE (programming kernel routing table)" << endl;
    }
    cout << endl;


    // ---------------------------------------------------------------
    // Step 4: Program routes into kernel
    // ---------------------------------------------------------------

    cout << "--- Step 4: Program routes into kernel ---" << endl;
    cout << endl;

    int success_count = 0;
    int skip_count = 0;
    int fail_count = 0;

    for (auto& route : best_routes) {
        // Skip connected routes — they're already in the kernel
        if (route.protocol == RouteProtocol::CONNECTED) {
            cout << "  " << left << setw(20) << route.prefix.to_string()
                 << "via " << setw(16) << route.next_hop
                 << "SKIP (connected)" << endl;
            skip_count++;
            continue;
        }

        auto result = programmer.add_route(route);

        if (result.success) {
            string status = programmer.is_dry_run() ? "OK (dry-run)" : "OK";
            cout << "  " << left << setw(20) << route.prefix.to_string()
                 << "via " << setw(16) << route.next_hop
                 << status << endl;
            global_programmed_routes.push_back(route);
            success_count++;
        } else {
            cout << "  " << left << setw(20) << route.prefix.to_string()
                 << "via " << setw(16) << route.next_hop
                 << "FAILED: " << result.error << endl;
            fail_count++;
        }
    }

    cout << endl;
    cout << "  Programmed: " << success_count
         << "  Skipped: " << skip_count
         << "  Failed: " << fail_count << endl;
    cout << endl;


    // ---------------------------------------------------------------
    // Step 5: Verify routes in kernel
    // ---------------------------------------------------------------

    cout << "--- Step 5: Verify routes in kernel ---" << endl;
    cout << endl;

    if (programmer.is_dry_run()) {
        cout << "  Skipping verification in dry-run mode" << endl;
        cout << "  Run with sudo to verify actual kernel routes" << endl;
    } else {
        auto kernel_routes = programmer.read_kernel_routes();

        int verified = 0;
        int missing = 0;

        for (auto& programmed : global_programmed_routes) {
            bool found = false;

            for (auto& kernel : kernel_routes) {
                if (kernel.prefix.network == programmed.prefix.network &&
                    kernel.prefix.length == programmed.prefix.length &&
                    kernel.next_hop == programmed.next_hop) {
                    found = true;
                    break;
                }
            }

            if (found) {
                cout << "  " << left << setw(20) << programmed.prefix.to_string()
                     << "via " << setw(16) << programmed.next_hop
                     << "VERIFIED" << endl;
                verified++;
            } else {
                cout << "  " << left << setw(20) << programmed.prefix.to_string()
                     << "via " << setw(16) << programmed.next_hop
                     << "MISSING" << endl;
                missing++;
            }
        }

        cout << endl;
        cout << "  Verified: " << verified << "  Missing: " << missing << endl;
    }
    cout << endl;


    // ---------------------------------------------------------------
    // Step 6: Cleanup
    // ---------------------------------------------------------------

    cout << "--- Step 6: Cleanup ---" << endl;
    cout << endl;

    for (auto& route : global_programmed_routes) {
        auto result = programmer.delete_route(route);

        string status;
        if (result.success) {
            status = programmer.is_dry_run() ? "OK (dry-run)" : "OK";
        } else {
            status = "FAILED: " + result.error;
        }

        cout << "  Deleting " << left << setw(20) << route.prefix.to_string()
             << status << endl;
    }

    global_programmed_routes.clear();
    programmer.close();

    cout << endl;
    cout << "  All routes cleaned up" << endl;
    cout << endl;

    return 0;
}
