#include "mrt_parser.h"
#include <iostream>
#include <cstring>

using namespace std;


MrtParser::MrtParser() : file(nullptr), record_count(0) {
}

bool MrtParser::open(const string& filename) {
    file = gzopen(filename.c_str(), "rb");
    if (!file) {
        return false;
    }
    return true;
}

void MrtParser::close() {
    if (file) {
        gzclose(file);
        file = nullptr;
    }
}

bool MrtParser::read_bytes(uint8_t* buffer, int length) {
    int total_read = 0;
    while (total_read < length) {
        int bytes_read = gzread(file, buffer + total_read, length - total_read);
        if (bytes_read <= 0) {
            return false;
        }
        total_read += bytes_read;
    }
    return true;
}

uint16_t MrtParser::read_uint16(const uint8_t* buf) {
    return (buf[0] << 8) | buf[1];
}

uint32_t MrtParser::read_uint32(const uint8_t* buf) {
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | buf[3];
}


bool MrtParser::parse_common_header(MrtHeader& header) {
    uint8_t buf[12];
    if (!read_bytes(buf, 12)) {
        return false;
    }

    header.timestamp = read_uint32(buf);
    header.type = read_uint16(buf + 4);
    header.subtype = read_uint16(buf + 6);
    header.length = read_uint32(buf + 8);

    return true;
}


bool MrtParser::parse_peer_index_table(const uint8_t* data, uint32_t length) {
    if (length < 8) return false;

    uint32_t offset = 0;

    // Collector BGP ID (4 bytes)
    offset += 4;

    // View name length (2 bytes) + view name
    if (offset + 2 > length) return false;
    uint16_t view_name_length = read_uint16(data + offset);
    offset += 2;
    offset += view_name_length;

    // Peer count (2 bytes)
    if (offset + 2 > length) return false;
    uint16_t peer_count = read_uint16(data + offset);
    offset += 2;

    peer_table.clear();
    peer_table.reserve(peer_count);

    for (int i = 0; i < peer_count; i++) {
        if (offset + 1 > length) return false;

        PeerEntry peer;
        peer.peer_type = data[offset];
        offset += 1;

        // Peer BGP ID (4 bytes)
        if (offset + 4 > length) return false;
        peer.peer_bgp_id = read_uint32(data + offset);
        offset += 4;

        // Peer IP address: 4 bytes for IPv4, 16 bytes for IPv6
        bool is_ipv6 = (peer.peer_type & 0x01) != 0;
        if (is_ipv6) {
            if (offset + 16 > length) return false;
            peer.peer_ip = 0;
            offset += 16;
        } else {
            if (offset + 4 > length) return false;
            peer.peer_ip = read_uint32(data + offset);
            offset += 4;
        }

        // Peer AS: 2 bytes for 16-bit, 4 bytes for 32-bit
        bool is_32bit_as = (peer.peer_type & 0x02) != 0;
        if (is_32bit_as) {
            if (offset + 4 > length) return false;
            peer.peer_as = read_uint32(data + offset);
            offset += 4;
        } else {
            if (offset + 2 > length) return false;
            peer.peer_as = read_uint16(data + offset);
            offset += 2;
        }

        peer_table.push_back(peer);
    }

    return true;
}


PathAttributes MrtParser::parse_bgp_attributes(const uint8_t* data, uint16_t length) {
    PathAttributes attrs;
    attrs.origin = Origin::IGP;
    attrs.next_hop = 0;
    attrs.local_pref = 0;
    attrs.med = 0;
    attrs.atomic_aggregate = false;
    attrs.aggregator_as = 0;
    attrs.aggregator_ip = 0;

    uint16_t offset = 0;

    while (offset < length) {
        if (offset + 2 > length) break;

        uint8_t flags = data[offset];
        uint8_t type_code = data[offset + 1];
        offset += 2;

        // Attribute length: 1 byte normally, 2 bytes if extended length flag set
        bool extended_length = (flags & 0x10) != 0;
        uint16_t attr_length;

        if (extended_length) {
            if (offset + 2 > length) break;
            attr_length = read_uint16(data + offset);
            offset += 2;
        } else {
            if (offset + 1 > length) break;
            attr_length = data[offset];
            offset += 1;
        }

        if (offset + attr_length > length) break;

        const uint8_t* attr_data = data + offset;

        switch (type_code) {
            case ATTR_ORIGIN: {
                if (attr_length >= 1) {
                    uint8_t origin_val = attr_data[0];
                    if (origin_val == 0) attrs.origin = Origin::IGP;
                    else if (origin_val == 1) attrs.origin = Origin::EGP;
                    else attrs.origin = Origin::INCOMPLETE;
                }
                break;
            }

            case ATTR_AS_PATH: {
                uint16_t as_offset = 0;
                while (as_offset + 2 <= attr_length) {
                    uint8_t segment_type = attr_data[as_offset];
                    uint8_t segment_count = attr_data[as_offset + 1];
                    as_offset += 2;

                    for (int i = 0; i < segment_count; i++) {
                        if (as_offset + 4 > attr_length) break;
                        uint32_t asn = read_uint32(attr_data + as_offset);
                        as_offset += 4;

                        if (segment_type == AS_SEQUENCE) {
                            attrs.as_path.push_back(asn);
                        } else if (segment_type == AS_SET) {
                            attrs.as_path.push_back(asn);
                        }
                    }
                }
                break;
            }

            case ATTR_NEXT_HOP: {
                if (attr_length >= 4) {
                    attrs.next_hop = read_uint32(attr_data);
                }
                break;
            }

            case ATTR_MED: {
                if (attr_length >= 4) {
                    attrs.med = read_uint32(attr_data);
                }
                break;
            }

            case ATTR_LOCAL_PREF: {
                if (attr_length >= 4) {
                    attrs.local_pref = read_uint32(attr_data);
                }
                break;
            }

            case ATTR_ATOMIC_AGGREGATE: {
                attrs.atomic_aggregate = true;
                break;
            }

            case ATTR_AGGREGATOR: {
                if (attr_length == 6) {
                    attrs.aggregator_as = read_uint16(attr_data);
                    attrs.aggregator_ip = read_uint32(attr_data + 2);
                } else if (attr_length == 8) {
                    attrs.aggregator_as = read_uint32(attr_data);
                    attrs.aggregator_ip = read_uint32(attr_data + 4);
                }
                break;
            }

            case ATTR_COMMUNITY: {
                for (uint16_t i = 0; i + 4 <= attr_length; i += 4) {
                    uint32_t community = read_uint32(attr_data + i);
                    attrs.communities.push_back(community);
                }
                break;
            }

            default:
                break;
        }

        offset += attr_length;
    }

    return attrs;
}


int MrtParser::parse_rib_ipv4_unicast(const uint8_t* data, uint32_t length,
                                       function<void(const Prefix&, const PathAttributes&, uint16_t peer_index)>& on_route) {
    if (length < 5) return 0;

    uint32_t offset = 0;

    // Sequence number (4 bytes)
    offset += 4;

    // Prefix length (1 byte)
    if (offset + 1 > length) return 0;
    uint8_t prefix_length = data[offset];
    offset += 1;

    // Prefix value: ceil(prefix_length / 8) bytes
    uint8_t prefix_bytes = (prefix_length + 7) / 8;
    if (offset + prefix_bytes > length) return 0;

    uint32_t network = 0;
    for (int i = 0; i < prefix_bytes; i++) {
        network |= ((uint32_t)data[offset + i]) << (24 - i * 8);
    }
    offset += prefix_bytes;

    Prefix prefix;
    prefix.network = network;
    prefix.length = prefix_length;

    // Entry count (2 bytes)
    if (offset + 2 > length) return 0;
    uint16_t entry_count = read_uint16(data + offset);
    offset += 2;

    int routes_parsed = 0;

    for (int i = 0; i < entry_count; i++) {
        if (offset + 8 > length) break;

        // Peer index (2 bytes)
        uint16_t peer_index = read_uint16(data + offset);
        offset += 2;

        // Originated time (4 bytes)
        offset += 4;

        // Attribute length (2 bytes)
        if (offset + 2 > length) break;
        uint16_t attr_length = read_uint16(data + offset);
        offset += 2;

        if (offset + attr_length > length) break;

        PathAttributes attrs = parse_bgp_attributes(data + offset, attr_length);
        offset += attr_length;

        on_route(prefix, attrs, peer_index);
        routes_parsed++;
    }

    return routes_parsed;
}


int MrtParser::parse_rib_dump(function<void(const Prefix&, const PathAttributes&, uint16_t peer_index)> on_route) {
    record_count = 0;
    int total_routes = 0;
    int prefix_count = 0;

    MrtHeader header;

    while (parse_common_header(header)) {
        // Read the record data
        vector<uint8_t> data(header.length);
        if (!read_bytes(data.data(), header.length)) {
            break;
        }

        if (header.type == MRT_TABLE_DUMP_V2) {
            if (header.subtype == MRT_SUBTYPE_PEER_INDEX_TABLE) {
                parse_peer_index_table(data.data(), header.length);
                cout << "  Peer index table: " << peer_table.size() << " peers" << endl;
            } else if (header.subtype == MRT_SUBTYPE_RIB_IPV4_UNICAST) {
                int routes = parse_rib_ipv4_unicast(data.data(), header.length, on_route);
                total_routes += routes;
                prefix_count++;

                if (prefix_count % 100000 == 0) {
                    cout << "  Parsed " << prefix_count << " prefixes..." << endl;
                }
            }
        }

        record_count++;
    }

    cout << "  Parse complete: " << prefix_count << " prefixes, "
         << total_routes << " route entries from "
         << peer_table.size() << " peers" << endl;

    return total_routes;
}


int MrtParser::get_peer_count() const {
    return peer_table.size();
}

int MrtParser::get_record_count() const {
    return record_count;
}

const PeerEntry& MrtParser::get_peer(uint16_t index) const {
    return peer_table[index];
}

const vector<PeerEntry>& MrtParser::get_peer_table() const {
    return peer_table;
}
