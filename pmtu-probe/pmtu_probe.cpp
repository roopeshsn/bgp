#include "pmtu_probe.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <cerrno>

using namespace std;


// ICMP checksum — same ones-complement algorithm used in IP and TCP.
// The checksum field must be zero before calculating.
uint16_t calculate_icmp_checksum(const uint8_t* data, int length) {
    uint32_t sum = 0;

    for (int i = 0; i < length; i += 2) {
        uint16_t word = (data[i] << 8);
        if (i + 1 < length) {
            word |= data[i + 1];
        }
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum & 0xFFFF;
}


// Create an ICMP socket with the Don't Fragment (DF) bit set.
// SOCK_DGRAM + IPPROTO_ICMP creates a non-privileged ICMP socket.
// The DF socket option differs between macOS and Linux:
//   macOS: IP_DONTFRAG = 1
//   Linux: IP_MTU_DISCOVER = IP_PMTUDISC_DO
int create_icmp_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        return -1;
    }

#ifdef __APPLE__
    int on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &on, sizeof(on)) < 0) {
        close(sock);
        return -1;
    }
#else
    int val = IP_PMTUDISC_DO;
    if (setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0) {
        close(sock);
        return -1;
    }
#endif

    return sock;
}


// Build an ICMP echo request packet with the given payload size.
// Total ICMP packet = 8 bytes header + payload_size bytes of data.
// The payload is filled with a pattern for identification.
void build_icmp_echo(uint8_t* buffer, int payload_size,
                     uint16_t sequence_number) {
    // ICMP type: 8 = Echo Request
    buffer[0] = ICMP_ECHO;

    // ICMP code: 0
    buffer[1] = 0;

    // Checksum placeholder (filled in later)
    buffer[2] = 0;
    buffer[3] = 0;

    // Identifier (use process ID)
    uint16_t id = getpid() & 0xFFFF;
    buffer[4] = (id >> 8) & 0xFF;
    buffer[5] = id & 0xFF;

    // Sequence number
    buffer[6] = (sequence_number >> 8) & 0xFF;
    buffer[7] = sequence_number & 0xFF;

    // Payload — fill with a repeating pattern
    for (int i = 0; i < payload_size; i++) {
        buffer[ICMP_HEADER_SIZE + i] = (uint8_t)(i & 0xFF);
    }

    // Calculate and fill in the checksum
    int total_size = ICMP_HEADER_SIZE + payload_size;
    uint16_t checksum = calculate_icmp_checksum(buffer, total_size);
    buffer[2] = (checksum >> 8) & 0xFF;
    buffer[3] = checksum & 0xFF;
}


// Send a single ICMP probe with the given payload size and wait for a reply.
// Returns REPLY if echo reply received, FRAGMENTATION_NEEDED if too large,
// TIMEOUT if no response, or ERROR on failure.
ProbeStatus send_probe(int sock, const string& target_ip, int payload_size,
                       int timeout_ms, uint16_t sequence_number) {
    // Build the ICMP echo request
    int icmp_packet_size = ICMP_HEADER_SIZE + payload_size;
    uint8_t send_buffer[65536];
    build_icmp_echo(send_buffer, payload_size, sequence_number);

    // Set up the destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, target_ip.c_str(), &dest_addr.sin_addr);

    // Send the probe
    ssize_t sent = sendto(sock, send_buffer, icmp_packet_size, 0,
                          (struct sockaddr*)&dest_addr, sizeof(dest_addr));

    if (sent < 0) {
        if (errno == EMSGSIZE) {
            cout << "(EMSGSIZE - blocked by local kernel, packet not sent) " << flush;
            return ProbeStatus::FRAGMENTATION_NEEDED;
        }
        return ProbeStatus::ERROR;
    }

    // Wait for a reply using poll()
    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLIN;

    int poll_result = poll(&pfd, 1, timeout_ms);

    if (poll_result < 0) {
        return ProbeStatus::ERROR;
    }

    if (poll_result == 0) {
        return ProbeStatus::TIMEOUT;
    }

    // Read the reply
    uint8_t recv_buffer[65536];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    ssize_t received = recvfrom(sock, recv_buffer, sizeof(recv_buffer), 0,
                                (struct sockaddr*)&from_addr, &from_len);

    if (received < 0) {
        return ProbeStatus::ERROR;
    }

    // On macOS SOCK_DGRAM ICMP, the kernel includes the IP header
    // in the response. We need to skip it to get to the ICMP data.
    int icmp_offset = 0;
    if (received > 0 && (recv_buffer[0] >> 4) == 4) {
        icmp_offset = (recv_buffer[0] & 0x0F) * 4;
    }

    if (received >= icmp_offset + ICMP_HEADER_SIZE) {
        uint8_t icmp_type = recv_buffer[icmp_offset];

        // Type 0 = Echo Reply — the packet got through
        if (icmp_type == ICMP_ECHOREPLY) {
            return ProbeStatus::REPLY;
        }

        // Type 3 = Destination Unreachable
        // Code 4 = Fragmentation Needed and DF Set
        if (icmp_type == ICMP_UNREACH) {
            uint8_t icmp_code = recv_buffer[icmp_offset + 1];
            if (icmp_code == ICMP_UNREACH_NEEDFRAG) {
                return ProbeStatus::FRAGMENTATION_NEEDED;
            }
        }
    }

    return ProbeStatus::TIMEOUT;
}


string probe_status_to_string(ProbeStatus status) {
    switch (status) {
        case ProbeStatus::REPLY:                return "OK";
        case ProbeStatus::FRAGMENTATION_NEEDED: return "Fragmentation needed";
        case ProbeStatus::TIMEOUT:              return "Timeout";
        case ProbeStatus::ERROR:                return "Error";
    }
    return "Unknown";
}


// Discover the path MTU using binary search.
// Sends ICMP probes at various sizes, narrowing down to the exact MTU.
ProbeResult discover_pmtu(const ProbeConfig& config) {
    ProbeResult result;
    result.target_ip = config.target_ip;
    result.success = false;

    int sock = create_icmp_socket();
    if (sock < 0) {
        result.error = "Failed to create ICMP socket (" + string(strerror(errno)) + ")";
        return result;
    }

    cout << "PMTU probe to " << config.target_ip << endl;
    cout << "Search range: " << config.min_mtu << " - " << config.max_mtu << " bytes" << endl;
    cout << endl;

    // Binary search for the path MTU.
    // We search in terms of ICMP payload size, then convert to full MTU at the end.
    // Full MTU = IP header (20) + ICMP header (8) + payload
    int min_payload = config.min_mtu - ICMP_OVERHEAD;
    int max_payload = config.max_mtu - ICMP_OVERHEAD;
    if (min_payload < 0) min_payload = 0;

    uint16_t sequence = 1;
    int largest_success = -1;

    // First, check if the maximum size works
    cout << "Probing with size " << (max_payload + ICMP_OVERHEAD)
         << " bytes... " << flush;

    ProbeStatus status = ProbeStatus::TIMEOUT;
    for (int attempt = 0; attempt < config.retries; attempt++) {
        status = send_probe(sock, config.target_ip, max_payload,
                            config.timeout_ms, sequence++);
        if (status != ProbeStatus::TIMEOUT) break;
    }

    cout << probe_status_to_string(status) << endl;

    if (status == ProbeStatus::REPLY) {
        // Max size works — PMTU is at least this large
        result.path_mtu = config.max_mtu;
        result.bgp_max_update = result.path_mtu - TCP_IP_OVERHEAD;
        result.success = true;
        close(sock);
        return result;
    }

    if (status == ProbeStatus::TIMEOUT) {
        // Can't reach the target at all — try minimum size
        cout << "Probing with size " << (min_payload + ICMP_OVERHEAD)
             << " bytes... " << flush;

        for (int attempt = 0; attempt < config.retries; attempt++) {
            status = send_probe(sock, config.target_ip, min_payload,
                                config.timeout_ms, sequence++);
            if (status != ProbeStatus::TIMEOUT) break;
        }

        cout << probe_status_to_string(status) << endl;

        if (status != ProbeStatus::REPLY) {
            result.error = "Target " + config.target_ip + " is unreachable";
            close(sock);
            return result;
        }
    }

    // Binary search between min and max
    int low = min_payload;
    int high = max_payload;

    // Track the largest payload that succeeded
    if (status == ProbeStatus::REPLY) {
        largest_success = max_payload;
    } else {
        largest_success = min_payload;
        low = min_payload;
        high = max_payload;
    }

    while (low < high) {
        int mid = low + (high - low + 1) / 2;
        int probe_mtu = mid + ICMP_OVERHEAD;

        cout << "Probing with size " << probe_mtu << " bytes... " << flush;

        ProbeStatus probe_result = ProbeStatus::TIMEOUT;
        for (int attempt = 0; attempt < config.retries; attempt++) {
            probe_result = send_probe(sock, config.target_ip, mid,
                                      config.timeout_ms, sequence++);
            if (probe_result != ProbeStatus::TIMEOUT) break;
        }

        cout << probe_status_to_string(probe_result) << endl;

        if (probe_result == ProbeStatus::REPLY) {
            low = mid;
            largest_success = mid;
        } else {
            high = mid - 1;
        }
    }

    close(sock);

    if (largest_success < 0) {
        result.error = "Could not determine PMTU";
        return result;
    }

    result.path_mtu = largest_success + ICMP_OVERHEAD;
    result.bgp_max_update = result.path_mtu - TCP_IP_OVERHEAD;
    result.success = true;
    return result;
}
