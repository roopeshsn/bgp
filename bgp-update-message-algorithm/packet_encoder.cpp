#include "packet_encoder.h"
#include <fstream>
#include <sstream>

// Byte encoding helpers, these write multi-byte values in network byte order (big-endian),
// which is the standard byte order for network protocols.

void write_uint8(vector<uint8_t>& buffer, uint8_t value) {
    buffer.push_back(value);
}

void write_uint16(vector<uint8_t>& buffer, uint16_t value) {
    buffer.push_back((value >> 8) & 0xFF);   // high byte first (big-endian)
    buffer.push_back(value & 0xFF);          // low byte second
}

void write_uint32(vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back((value >> 24) & 0xFF);  // most significant byte first
    buffer.push_back((value >> 16) & 0xFF);
    buffer.push_back((value >> 8) & 0xFF);
    buffer.push_back(value & 0xFF);          // least significant byte last
}

// Convert an IPv4 address string like "192.168.1.1" into a 32-bit integer
// in network byte order. We parse each octet and shift it into position.
uint32_t parse_ipv4(const string& ip) {
    uint32_t result = 0;
    istringstream stream(ip);
    string octet;
    int shift = 24;

    while (getline(stream, octet, '.')) {
        result |= (stoi(octet) << shift);
        shift -= 8;
    }

    return result;
}

// BGP UPDATE message encoding (RFC 4271 Section 4.3)
// Encode a single NLRI prefix into wire format.
// Format: 1 byte prefix length, then ceil(length/8) bytes of the prefix address.
// Only the significant bits are sent — e.g., a /24 sends 3 bytes of the address.
void encode_nlri_prefix(vector<uint8_t>& buffer, const Prefix& prefix) {
    write_uint8(buffer, prefix.length);

    uint32_t ip = parse_ipv4(prefix.network);
    int num_bytes = (prefix.length + 7) / 8;
    for (int i = 0; i < num_bytes; i++) {
        write_uint8(buffer, (ip >> (24 - i * 8)) & 0xFF);
    }
}

// Encode all path attributes into wire format.
// Each attribute has: 1 byte flags, 1 byte type code, 1 byte length, then the value.
//
// Attribute flags:
//   Bit 7 (0x80): Optional (0 = well-known, 1 = optional)
//   Bit 6 (0x40): Transitive (1 = transitive)
//   Bit 5 (0x20): Partial (1 = partial)
//   Bit 4 (0x10): Extended Length (1 = 2-byte length field)
//
// Well-known mandatory:    flags = 0x40 (transitive)
// Well-known discretionary: flags = 0x40 (transitive)
// Optional transitive:     flags = 0xC0 (optional + transitive)
// Optional non-transitive: flags = 0x80 (optional)
void encode_path_attributes(vector<uint8_t>& buffer, const PathAttributes& attrs) {

    // ORIGIN (Type 1) — well-known mandatory
    // Value: 0 = IGP, 1 = EGP, 2 = INCOMPLETE
    write_uint8(buffer, 0x40);                           // flags: well-known, transitive
    write_uint8(buffer, 1);                              // type code: ORIGIN
    write_uint8(buffer, 1);                              // length: 1 byte
    write_uint8(buffer, static_cast<uint8_t>(attrs.origin));  // value

    // AS_PATH (Type 2) — well-known mandatory
    // Value: one AS_SEQUENCE segment containing all ASNs
    // Segment format: 1 byte type (2=SEQUENCE) + 1 byte count + 4 bytes per ASN
    uint8_t as_path_value_len = 2 + (attrs.as_path.size() * 4);
    write_uint8(buffer, 0x40);                           // flags: well-known, transitive
    write_uint8(buffer, 2);                              // type code: AS_PATH
    write_uint8(buffer, as_path_value_len);              // length
    write_uint8(buffer, 2);                              // segment type: AS_SEQUENCE
    write_uint8(buffer, attrs.as_path.size());           // number of ASNs in segment
    for (uint32_t asn : attrs.as_path) {
        write_uint32(buffer, asn);
    }

    // NEXT_HOP (Type 3) — well-known mandatory
    // Value: 4 bytes IPv4 address
    write_uint8(buffer, 0x40);                           // flags: well-known, transitive
    write_uint8(buffer, 3);                              // type code: NEXT_HOP
    write_uint8(buffer, 4);                              // length: 4 bytes
    uint32_t next_hop_ip = parse_ipv4(attrs.next_hop);
    write_uint32(buffer, next_hop_ip);

    // MULTI_EXIT_DISC / MED (Type 4) — optional non-transitive
    // Value: 4 bytes unsigned integer
    write_uint8(buffer, 0x80);                           // flags: optional, non-transitive
    write_uint8(buffer, 4);                              // type code: MED
    write_uint8(buffer, 4);                              // length: 4 bytes
    write_uint32(buffer, attrs.med);

    // LOCAL_PREF (Type 5) — well-known discretionary
    // Value: 4 bytes unsigned integer
    write_uint8(buffer, 0x40);                           // flags: well-known, transitive
    write_uint8(buffer, 5);                              // type code: LOCAL_PREF
    write_uint8(buffer, 4);                              // length: 4 bytes
    write_uint32(buffer, attrs.local_pref);

    // ATOMIC_AGGREGATE (Type 6) — well-known discretionary
    // Value: 0 bytes (it's just a flag — presence means "set")
    if (attrs.atomic_aggregate) {
        write_uint8(buffer, 0x40);                       // flags: well-known, transitive
        write_uint8(buffer, 6);                          // type code: ATOMIC_AGGREGATE
        write_uint8(buffer, 0);                          // length: 0 bytes
    }

    // AGGREGATOR (Type 7) — optional transitive
    // Value: 2 bytes AS number + 4 bytes IP address
    if (attrs.aggregator_as != 0) {
        write_uint8(buffer, 0xC0);                       // flags: optional, transitive
        write_uint8(buffer, 7);                          // type code: AGGREGATOR
        write_uint8(buffer, 6);                          // length: 6 bytes
        write_uint16(buffer, attrs.aggregator_as);       // 2-byte AS number
        uint32_t agg_ip = parse_ipv4(attrs.aggregator_ip);
        write_uint32(buffer, agg_ip);
    }

    // COMMUNITY (Type 8) — optional transitive
    // Value: 4 bytes per community value
    if (!attrs.communities.empty()) {
        write_uint8(buffer, 0xC0);                       // flags: optional, transitive
        write_uint8(buffer, 8);                          // type code: COMMUNITY
        write_uint8(buffer, attrs.communities.size() * 4); // length
        for (uint32_t community : attrs.communities) {
            write_uint32(buffer, community);
        }
    }
}

// Encode a complete BGP UPDATE message including the BGP header.
// Returns the raw bytes ready to be wrapped in TCP/IP/Ethernet.
vector<uint8_t> encode_bgp_update(const BGPUpdateMessage& msg) {
    // First, encode the path attributes and NLRI into temporary buffers
    // so we can calculate their lengths for the header fields.
    vector<uint8_t> path_attrs_bytes;
    encode_path_attributes(path_attrs_bytes, msg.attributes);

    vector<uint8_t> nlri_bytes;
    for (const auto& prefix : msg.nlri) {
        encode_nlri_prefix(nlri_bytes, prefix);
    }

    // Calculate the total BGP message length
    uint16_t bgp_message_length = BGP_HEADER_SIZE
                                + BGP_WITHDRAWN_LENGTH_FIELD
                                + BGP_PATH_ATTR_LENGTH_FIELD
                                + path_attrs_bytes.size()
                                + nlri_bytes.size();

    // Now build the complete BGP message
    vector<uint8_t> bgp_message;

    // BGP Marker: 16 bytes of 0xFF (used by receivers to find message boundaries)
    for (int i = 0; i < 16; i++) {
        write_uint8(bgp_message, 0xFF);
    }

    // BGP Length: total message length including header
    write_uint16(bgp_message, bgp_message_length);

    // BGP Type: 2 = UPDATE
    write_uint8(bgp_message, 2);

    // Withdrawn Routes Length: 0 (we're only advertising, not withdrawing)
    write_uint16(bgp_message, 0);

    // Total Path Attribute Length
    write_uint16(bgp_message, path_attrs_bytes.size());

    // Path Attributes
    bgp_message.insert(bgp_message.end(),
                       path_attrs_bytes.begin(),
                       path_attrs_bytes.end());

    // NLRI (Network Layer Reachability Information)
    bgp_message.insert(bgp_message.end(),
                       nlri_bytes.begin(),
                       nlri_bytes.end());

    return bgp_message;
}


// Network layer header builders
// These construct the Ethernet, IP, and TCP headers that wrap
// around the BGP message to form a complete network packet.

// Build a 14-byte Ethernet frame header.
// Uses mock MAC addresses since we're writing to a pcap file, not a real network.
vector<uint8_t> build_ethernet_header() {
    vector<uint8_t> header;

    // Destination MAC: AA:BB:CC:DD:EE:02
    uint8_t dst_mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02};
    for (int i = 0; i < 6; i++) {
        write_uint8(header, dst_mac[i]);
    }

    // Source MAC: AA:BB:CC:DD:EE:01
    uint8_t src_mac[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    for (int i = 0; i < 6; i++) {
        write_uint8(header, src_mac[i]);
    }

    // EtherType: 0x0800 = IPv4
    write_uint16(header, 0x0800);

    return header;
}

// Calculate the IP header checksum.
// This is the standard ones-complement sum used in IP, TCP, and UDP.
// The checksum field itself must be set to 0 before calculating.
uint16_t calculate_ip_checksum(const vector<uint8_t>& header) {
    uint32_t sum = 0;

    // Sum all 16-bit words in the header
    for (size_t i = 0; i < header.size(); i += 2) {
        uint16_t word = (header[i] << 8);
        if (i + 1 < header.size()) {
            word |= header[i + 1];
        }
        sum += word;
    }

    // Fold any carry bits from the upper 16 bits back into the lower 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Take the ones-complement (flip all bits)
    return ~sum & 0xFFFF;
}

// Build a 20-byte IPv4 header.
// total_length = IP header (20) + TCP header (20) + BGP payload size
vector<uint8_t> build_ip_header(uint16_t total_length) {
    vector<uint8_t> header;

    // Version (4) and IHL (5 = 20 bytes, no options) — combined into one byte
    write_uint8(header, 0x45);

    // DSCP / ECN (Type of Service) — 0 for normal traffic
    write_uint8(header, 0x00);

    // Total Length: entire IP packet including header
    write_uint16(header, total_length);

    // Identification: packet ID for fragmentation reassembly
    write_uint16(header, 0x0001);

    // Flags (Don't Fragment) + Fragment Offset (0)
    write_uint16(header, 0x4000);

    // TTL: 64 hops (standard default)
    write_uint8(header, 64);

    // Protocol: 6 = TCP
    write_uint8(header, 6);

    // Header Checksum: set to 0 first, calculate after header is complete
    write_uint16(header, 0x0000);

    // Source IP: 192.168.1.1 (mock BGP router)
    write_uint32(header, parse_ipv4("192.168.1.1"));

    // Destination IP: 192.168.1.2 (mock BGP peer)
    write_uint32(header, parse_ipv4("192.168.1.2"));

    // Now calculate and fill in the checksum
    uint16_t checksum = calculate_ip_checksum(header);
    header[10] = (checksum >> 8) & 0xFF;
    header[11] = checksum & 0xFF;

    return header;
}

// Build a 20-byte TCP header.
// seq_num increments per message to simulate a TCP stream.
// We set checksum to 0 — Wireshark will flag it but still decodes BGP fine.
vector<uint8_t> build_tcp_header(uint32_t seq_num) {
    vector<uint8_t> header;

    // Source Port: 50000 (ephemeral port)
    write_uint16(header, 50000);

    // Destination Port: 179 (BGP well-known port)
    write_uint16(header, 179);

    // Sequence Number
    write_uint32(header, seq_num);

    // Acknowledgment Number
    write_uint32(header, 1);

    // Data Offset (5 = 20 bytes, no options) shifted left 4 bits, plus reserved bits
    write_uint8(header, 0x50);

    // TCP Flags: PSH + ACK (0x18)
    // PSH tells the receiver to deliver data to the application immediately
    // ACK acknowledges received data
    write_uint8(header, 0x18);

    // Window Size: 65535 (maximum)
    write_uint16(header, 65535);

    // Checksum: 0 (not calculated — Wireshark will warn but still decode)
    write_uint16(header, 0x0000);

    // Urgent Pointer: 0 (not used)
    write_uint16(header, 0x0000);

    return header;
}

// Build a complete network packet (Ethernet + IP + TCP + BGP)
vector<uint8_t> build_packet(const vector<uint8_t>& bgp_bytes, uint32_t tcp_seq_num) {
    vector<uint8_t> ethernet_header = build_ethernet_header();

    uint16_t ip_total_length = 20 + 20 + bgp_bytes.size();  // IP + TCP + BGP
    vector<uint8_t> ip_header = build_ip_header(ip_total_length);

    vector<uint8_t> tcp_header = build_tcp_header(tcp_seq_num);

    // Assemble: Ethernet + IP + TCP + BGP
    vector<uint8_t> packet;
    packet.insert(packet.end(), ethernet_header.begin(), ethernet_header.end());
    packet.insert(packet.end(), ip_header.begin(), ip_header.end());
    packet.insert(packet.end(), tcp_header.begin(), tcp_header.end());
    packet.insert(packet.end(), bgp_bytes.begin(), bgp_bytes.end());

    return packet;
}

// Write all packets to a .pcap file that Wireshark can open.
void write_pcap_file(const string& filename, const vector<vector<uint8_t>>& packets) {
    ofstream file(filename, ios::binary);

    // PCAP Global Header (24 bytes)

    // Magic number: identifies this as a pcap file and indicates byte order
    uint32_t magic = 0xA1B2C3D4;
    file.write(reinterpret_cast<const char*>(&magic), 4);

    // Version: 2.4 is the standard pcap version
    uint16_t version_major = 2;
    uint16_t version_minor = 4;
    file.write(reinterpret_cast<const char*>(&version_major), 2);
    file.write(reinterpret_cast<const char*>(&version_minor), 2);

    // Timezone offset and timestamp accuracy — always 0 in practice
    uint32_t thiszone = 0;
    uint32_t sigfigs = 0;
    file.write(reinterpret_cast<const char*>(&thiszone), 4);
    file.write(reinterpret_cast<const char*>(&sigfigs), 4);

    // Snap length: maximum bytes captured per packet
    uint32_t snaplen = 65535;
    file.write(reinterpret_cast<const char*>(&snaplen), 4);

    // Link-layer type: 1 = Ethernet
    uint32_t link_type = 1;
    file.write(reinterpret_cast<const char*>(&link_type), 4);

    // === Write each packet ===
    for (size_t i = 0; i < packets.size(); i++) {
        const auto& packet = packets[i];

        // Packet header (16 bytes)
        uint32_t ts_sec = i;      // each packet gets a different timestamp second
        uint32_t ts_usec = 0;
        uint32_t cap_len = packet.size();
        uint32_t orig_len = packet.size();

        file.write(reinterpret_cast<const char*>(&ts_sec), 4);
        file.write(reinterpret_cast<const char*>(&ts_usec), 4);
        file.write(reinterpret_cast<const char*>(&cap_len), 4);
        file.write(reinterpret_cast<const char*>(&orig_len), 4);

        // Packet data
        file.write(reinterpret_cast<const char*>(packet.data()), packet.size());
    }

    file.close();
}
