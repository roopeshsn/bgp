#include "update_parser.h"
#include <cstring>

using namespace std;


static uint16_t read_uint16(const uint8_t* data) {
    return (data[0] << 8) | data[1];
}

static uint32_t read_uint32(const uint8_t* data) {
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

static string bytes_to_ip(const uint8_t* bytes, int num_bytes) {
    uint8_t octets[4] = {0, 0, 0, 0};
    for (int i = 0; i < num_bytes && i < 4; i++) {
        octets[i] = bytes[i];
    }
    return to_string(octets[0]) + "." + to_string(octets[1]) + "."
         + to_string(octets[2]) + "." + to_string(octets[3]);
}

static int parse_prefix_list(const uint8_t* data, int length, vector<Prefix>& out) {
    int pos = 0;

    while (pos < length) {
        if (pos >= length) return -1;

        uint8_t prefix_len = data[pos++];
        int num_bytes = (prefix_len + 7) / 8;

        if (pos + num_bytes > length) return -1;

        Prefix prefix;
        prefix.length = prefix_len;
        prefix.network = bytes_to_ip(data + pos, num_bytes);
        out.push_back(prefix);

        pos += num_bytes;
    }

    return pos;
}

static bool parse_path_attributes(const uint8_t* data, int length, PathAttributes& attrs) {
    attrs.origin = Origin::IGP;
    attrs.local_pref = 0;
    attrs.med = 0;
    attrs.atomic_aggregate = false;
    attrs.aggregator_as = 0;
    attrs.as_path.clear();
    attrs.communities.clear();
    attrs.next_hop = "";
    attrs.aggregator_ip = "";

    int pos = 0;

    while (pos < length) {
        if (pos + 3 > length) return false;

        uint8_t flags = data[pos++];
        uint8_t type_code = data[pos++];

        uint16_t attr_length;
        if (flags & 0x10) {
            if (pos + 2 > length) return false;
            attr_length = read_uint16(data + pos);
            pos += 2;
        } else {
            attr_length = data[pos++];
        }

        if (pos + attr_length > length) return false;

        const uint8_t* value = data + pos;

        switch (type_code) {
            case 1: // ORIGIN
                if (attr_length >= 1) {
                    attrs.origin = static_cast<Origin>(value[0]);
                }
                break;

            case 2: { // AS_PATH
                int ap = 0;
                while (ap + 2 <= (int)attr_length) {
                    uint8_t segment_type = value[ap++];
                    uint8_t segment_count = value[ap++];

                    for (int i = 0; i < segment_count && ap + 4 <= (int)attr_length; i++) {
                        uint32_t asn = read_uint32(value + ap);
                        attrs.as_path.push_back(asn);
                        ap += 4;
                    }
                }
                break;
            }

            case 3: // NEXT_HOP
                if (attr_length >= 4) {
                    attrs.next_hop = bytes_to_ip(value, 4);
                }
                break;

            case 4: // MULTI_EXIT_DISC (MED)
                if (attr_length >= 4) {
                    attrs.med = read_uint32(value);
                }
                break;

            case 5: // LOCAL_PREF
                if (attr_length >= 4) {
                    attrs.local_pref = read_uint32(value);
                }
                break;

            case 6: // ATOMIC_AGGREGATE
                attrs.atomic_aggregate = true;
                break;

            case 7: // AGGREGATOR
                if (attr_length >= 6) {
                    attrs.aggregator_as = read_uint16(value);
                    attrs.aggregator_ip = bytes_to_ip(value + 2, 4);
                } else if (attr_length >= 8) {
                    attrs.aggregator_as = read_uint32(value);
                    attrs.aggregator_ip = bytes_to_ip(value + 4, 4);
                }
                break;

            case 8: // COMMUNITY
                for (int i = 0; i + 4 <= (int)attr_length; i += 4) {
                    attrs.communities.push_back(read_uint32(value + i));
                }
                break;

            default:
                break;
        }

        pos += attr_length;
    }

    return true;
}


bool parse_update(const uint8_t* data, uint16_t length, ParsedUpdate& result) {
    result.withdrawn_routes.clear();
    result.nlri.clear();
    result.has_attributes = false;

    int pos = 0;

    // Withdrawn Routes Length
    if (pos + 2 > length) return false;
    uint16_t withdrawn_length = read_uint16(data + pos);
    pos += 2;

    // Withdrawn Routes
    if (pos + withdrawn_length > length) return false;
    if (withdrawn_length > 0) {
        int consumed = parse_prefix_list(data + pos, withdrawn_length, result.withdrawn_routes);
        if (consumed < 0) return false;
    }
    pos += withdrawn_length;

    // Total Path Attribute Length
    if (pos + 2 > length) return false;
    uint16_t path_attr_length = read_uint16(data + pos);
    pos += 2;

    // Path Attributes
    if (pos + path_attr_length > length) return false;
    if (path_attr_length > 0) {
        if (!parse_path_attributes(data + pos, path_attr_length, result.attributes)) {
            return false;
        }
        result.has_attributes = true;
    }
    pos += path_attr_length;

    // NLRI (remaining bytes)
    int nlri_length = length - pos;
    if (nlri_length > 0) {
        int consumed = parse_prefix_list(data + pos, nlri_length, result.nlri);
        if (consumed < 0) return false;
    }

    return true;
}
