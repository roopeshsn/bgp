#ifndef PMTU_PROBE_H
#define PMTU_PROBE_H

#include <string>
#include <cstdint>

using namespace std;

// Overhead constants
const int IP_HEADER_SIZE   = 20;
const int ICMP_HEADER_SIZE = 8;
const int TCP_HEADER_SIZE  = 20;
const int ICMP_OVERHEAD    = IP_HEADER_SIZE + ICMP_HEADER_SIZE;  // 28 bytes
const int TCP_IP_OVERHEAD  = IP_HEADER_SIZE + TCP_HEADER_SIZE;   // 40 bytes

// Result of a single probe attempt
enum class ProbeStatus {
    REPLY,                  // echo reply received — size fits
    FRAGMENTATION_NEEDED,   // packet too large — ICMP error or sendto() failed with EMSGSIZE
    TIMEOUT,                // no response within timeout
    ERROR                   // socket or system error
};

// Configuration for the PMTU discovery
struct ProbeConfig {
    string target_ip;
    int max_mtu;            // upper bound for binary search (default 1500)
    int min_mtu;            // lower bound for binary search (default 68)
    int timeout_ms;         // how long to wait for each reply (default 2000)
    int retries;            // retries per probe size (default 2)
};

// Final result of PMTU discovery
struct ProbeResult {
    string target_ip;
    int path_mtu;           // discovered path MTU in bytes (IP + payload)
    int bgp_max_update;     // usable bytes for BGP after TCP/IP headers
    bool success;
    string error;
};

// Discover the path MTU to a target IP address.
// Sends ICMP echo requests with DF bit set at various sizes,
// using binary search to find the largest size that gets through.
ProbeResult discover_pmtu(const ProbeConfig& config);

#endif
