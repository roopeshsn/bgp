#include <iostream>
#include "pmtu_probe.h"

using namespace std;

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);

    if (argc < 2) {
        cout << "Usage: " << argv[0] << " <target_ip> [max_mtu]" << endl;
        cout << endl;
        cout << "Examples:" << endl;
        cout << "  " << argv[0] << " 8.8.8.8          # probe with default max 1500" << endl;
        cout << "  " << argv[0] << " 10.0.0.2 9000    # probe jumbo frame path" << endl;
        return 1;
    }

    ProbeConfig config;
    config.target_ip  = argv[1];
    config.min_mtu    = 68;
    config.max_mtu    = 1500;
    config.timeout_ms = 2000;
    config.retries    = 2;

    if (argc >= 3) {
        config.max_mtu = stoi(argv[2]);
    }

    cout << endl;
    ProbeResult result = discover_pmtu(config);
    cout << endl;

    if (!result.success) {
        cout << "PMTU discovery failed: " << result.error << endl;
        return 1;
    }

    cout << "--- Results ---" << endl;
    cout << "Path MTU to " << result.target_ip << ": "
         << result.path_mtu << " bytes" << endl;
    cout << "BGP max UPDATE size at this PMTU: "
         << result.bgp_max_update << " bytes "
         << "(PMTU " << result.path_mtu
         << " - " << TCP_IP_OVERHEAD << " TCP/IP headers)" << endl;

    if (result.bgp_max_update < 4096) {
        cout << "WARNING: BGP UPDATE messages can be up to 4096 bytes. "
             << "This path may cause large UPDATE messages to be dropped." << endl;
    }

    return 0;
}
