#include <iostream>
#include <unordered_map>
#include "bgp_types.h"
#include "packet_encoder.h"

size_t calculate_prefix_size(const Prefix& prefix) {
    // 1 byte for prefix length + ceil(prefix_length / 8) bytes for the prefix itself
    return 1 + (prefix.length + 7) / 8;
}

size_t calculate_attributes_size(const PathAttributes& attrs) {
    size_t size = 0;

    // ORIGIN: 1 flag + 1 type + 1 length + 1 value = 4 bytes
    size += 4;

    // AS_PATH: 3 bytes header + 2 bytes (segment type + count) + 4 bytes per ASN
    size += 3 + 2 + (attrs.as_path.size() * 4);

    // NEXT_HOP: 3 bytes header + 4 bytes IPv4 address
    size += 3 + 4;

    // LOCAL_PREF: 3 bytes header + 4 bytes value
    size += 3 + 4;

    // MED: 3 bytes header + 4 bytes value
    size += 3 + 4;

    // COMMUNITY: only present if non-empty
    if (!attrs.communities.empty()) {
        size += 3 + (attrs.communities.size() * 4);
    }

    // ATOMIC_AGGREGATE: only present if set, 3 bytes header + 0 bytes value
    if (attrs.atomic_aggregate) {
        size += 3;
    }

    // AGGREGATOR: only present if set, 3 bytes header + 2 bytes AS + 4 bytes IP
    if (attrs.aggregator_as != 0) {
        size += 3 + 2 + 4;
    }

    return size;
}

vector<BGPUpdateMessage> generate_update_messages(
    const unordered_map<PathAttributes, vector<Prefix>, PathAttributesHash>& groups
) {
    vector<BGPUpdateMessage> messages;

    for (const auto& [attrs, prefixes] : groups) {
        size_t attrs_size = calculate_attributes_size(attrs);
        size_t fixed_overhead = BGP_HEADER_SIZE
                              + BGP_WITHDRAWN_LENGTH_FIELD
                              + BGP_PATH_ATTR_LENGTH_FIELD
                              + attrs_size;
        size_t max_nlri_space = BGP_MAX_MESSAGE_SIZE - fixed_overhead;

        BGPUpdateMessage current_message;
        current_message.attributes = attrs;
        size_t current_nlri_size = 0;

        for (const auto& prefix : prefixes) {
            size_t prefix_size = calculate_prefix_size(prefix);

            if (current_nlri_size + prefix_size > max_nlri_space
                && !current_message.nlri.empty()) {
                current_message.message_size = fixed_overhead + current_nlri_size;
                messages.push_back(current_message);

                current_message.nlri.clear();
                current_nlri_size = 0;
            }

            current_message.nlri.push_back(prefix);
            current_nlri_size += prefix_size;
        }

        if (!current_message.nlri.empty()) {
            current_message.message_size = fixed_overhead + current_nlri_size;
            messages.push_back(current_message);
        }
    }

    return messages;
}

string origin_to_string(Origin o) {
    switch (o) {
        case Origin::IGP:        return "IGP";
        case Origin::EGP:        return "EGP";
        case Origin::INCOMPLETE: return "INCOMPLETE";
    }
    return "UNKNOWN";
}

void print_attributes(const PathAttributes& attrs, const string& indent) {
    cout << indent << "Origin:     " << origin_to_string(attrs.origin) << "\n";

    cout << indent << "AS_PATH:    ";
    for (size_t i = 0; i < attrs.as_path.size(); i++) {
        if (i > 0) cout << " ";
        cout << attrs.as_path[i];
    }
    cout << "\n";

    cout << indent << "NEXT_HOP:   " << attrs.next_hop << "\n";
    cout << indent << "LOCAL_PREF: " << attrs.local_pref << "\n";
    cout << indent << "MED:        " << attrs.med << "\n";

    cout << indent << "COMMUNITY:  ";
    for (size_t i = 0; i < attrs.communities.size(); i++) {
        if (i > 0) cout << " ";
        cout << (attrs.communities[i] >> 16)
             << ":" << (attrs.communities[i] & 0xFFFF);
    }
    if (attrs.communities.empty()) cout << "(none)";
    cout << "\n";

    cout << indent << "ATOMIC_AGG: " << (attrs.atomic_aggregate ? "yes" : "no") << "\n";

    if (attrs.aggregator_as != 0) {
        cout << indent << "AGGREGATOR: AS" << attrs.aggregator_as
             << " " << attrs.aggregator_ip << "\n";
    }
}

void print_route(const Route& route) {
    cout << "  Prefix: " << route.prefix.network
         << "/" << (int)route.prefix.length << "\n";
    print_attributes(route.attributes, "    ");
    cout << "\n";
}

int main() {
    vector<Route> routes = {
        // Group A: learned via peer 192.168.1.1 (AS 65002)
        {{"10.1.0.0",    16}, {Origin::IGP, {65001, 65002},         "192.168.1.1", 100, 0,  {(65001u<<16)|100, (65001u<<16)|200}, false, 0, ""}},
        {{"10.2.0.0",    16}, {Origin::IGP, {65001, 65002},         "192.168.1.1", 100, 0,  {(65001u<<16)|100, (65001u<<16)|200}, false, 0, ""}},
        {{"10.3.0.0",    24}, {Origin::IGP, {65001, 65002},         "192.168.1.1", 100, 0,  {(65001u<<16)|100, (65001u<<16)|200}, false, 0, ""}},
        {{"10.4.0.0",    22}, {Origin::IGP, {65001, 65002},         "192.168.1.1", 100, 0,  {(65001u<<16)|100, (65001u<<16)|200}, false, 0, ""}},
        {{"10.10.0.0",   15}, {Origin::IGP, {65001, 65002},         "192.168.1.1", 100, 0,  {(65001u<<16)|100, (65001u<<16)|200}, false, 0, ""}},

        // Group B: learned via peer 192.168.2.1 (AS 65003 -> 65004)
        {{"172.16.0.0",  16}, {Origin::IGP, {65001, 65003, 65004},  "192.168.2.1", 100, 50, {(65003u<<16)|300}, false, 0, ""}},
        {{"172.16.1.0",  24}, {Origin::IGP, {65001, 65003, 65004},  "192.168.2.1", 100, 50, {(65003u<<16)|300}, false, 0, ""}},
        {{"172.16.2.0",  24}, {Origin::IGP, {65001, 65003, 65004},  "192.168.2.1", 100, 50, {(65003u<<16)|300}, false, 0, ""}},
        {{"172.16.3.0",  24}, {Origin::IGP, {65001, 65003, 65004},  "192.168.2.1", 100, 50, {(65003u<<16)|300}, false, 0, ""}},

        // Group C: aggregated route
        {{"192.168.10.0", 24}, {Origin::EGP, {65001, 65005},        "10.0.0.1",   200, 10, {}, true, 65005, "10.0.0.1"}},

        // Group D: learned via peer 10.0.0.2 (AS 65006 -> 65007), high local pref
        {{"203.0.113.0",  24}, {Origin::IGP, {65001, 65006, 65007}, "10.0.0.2",   150, 0,  {(65006u<<16)|500}, false, 0, ""}},
        {{"198.51.100.0", 24}, {Origin::IGP, {65001, 65006, 65007}, "10.0.0.2",   150, 0,  {(65006u<<16)|500}, false, 0, ""}},
        {{"198.51.101.0", 24}, {Origin::IGP, {65001, 65006, 65007}, "10.0.0.2",   150, 0,  {(65006u<<16)|500}, false, 0, ""}},

        // Group E: directly connected / redistributed routes
        {{"192.168.1.0",  24}, {Origin::INCOMPLETE, {65001},        "0.0.0.0",    100, 0,  {}, false, 0, ""}},
        {{"192.168.2.0",  24}, {Origin::INCOMPLETE, {65001},        "0.0.0.0",    100, 0,  {}, false, 0, ""}},
    };

    // Group F: large group to test message splitting
    PathAttributes large_group_attrs = {
        Origin::IGP, {65001, 65010, 65011, 65012}, "10.10.10.1", 100, 0,
        {(65010u<<16)|100, (65010u<<16)|200, (65010u<<16)|300}, false, 0, ""
    };
    for (int i = 0; i < 2000; i++) {
        string network = "100." + to_string(i / 256) + "." + to_string(i % 256) + ".0";
        routes.push_back({Prefix{network, 24}, large_group_attrs});
    }

    cout << "=== BGP Route Table ===\n\n";
    for (const auto& route : routes) {
        print_route(route);
    }

    // Grouping: group prefixes by common path attributes
    unordered_map<PathAttributes, vector<Prefix>, PathAttributesHash> groups;
    for (const auto& route : routes) {
        groups[route.attributes].push_back(route.prefix);
    }

    // Generate size-aware UPDATE messages
    vector<BGPUpdateMessage> messages = generate_update_messages(groups);

    cout << "=== BGP UPDATE Messages ===\n";
    cout << "Total messages: " << messages.size()
         << " (from " << groups.size() << " groups)\n\n";

    int msg_num = 1;
    for (const auto& msg : messages) {
        cout << "UPDATE Message #" << msg_num++ << "\n";
        cout << "  Size: " << msg.message_size << " / "
             << BGP_MAX_MESSAGE_SIZE << " bytes\n";
        cout << "  Path Attributes:\n";
        print_attributes(msg.attributes, "    ");
        cout << "  NLRI (" << msg.nlri.size() << " prefixes):\n";
        for (const auto& p : msg.nlri) {
            cout << "    " << p.network << "/" << (int)p.length << "\n";
        }
        cout << "\n";
    }

    // Encode UPDATE messages into packets and write to pcap file
    vector<vector<uint8_t>> packets;
    uint32_t tcp_seq_num = 1;

    for (const auto& msg : messages) {
        vector<uint8_t> bgp_bytes = encode_bgp_update(msg);
        vector<uint8_t> packet = build_packet(bgp_bytes, tcp_seq_num);
        packets.push_back(packet);
        tcp_seq_num += bgp_bytes.size();
    }

    string pcap_filename = "bgp_updates.pcap";
    write_pcap_file(pcap_filename, packets);
    cout << "=== PCAP file written: " << pcap_filename
         << " (" << packets.size() << " packets) ===\n";
   
    return 0;
}
