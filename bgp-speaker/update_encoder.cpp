#include "update_encoder.h"
#include <cstring>
#include <sstream>

using namespace std;


static void write_uint8(vector<uint8_t>& buf, uint8_t val) {
    buf.push_back(val);
}

static void write_uint16(vector<uint8_t>& buf, uint16_t val) {
    buf.push_back((val >> 8) & 0xFF);
    buf.push_back(val & 0xFF);
}

static void write_uint32(vector<uint8_t>& buf, uint32_t val) {
    buf.push_back((val >> 24) & 0xFF);
    buf.push_back((val >> 16) & 0xFF);
    buf.push_back((val >> 8) & 0xFF);
    buf.push_back(val & 0xFF);
}

static uint32_t parse_ipv4(const string& ip) {
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

static void encode_nlri_prefix(vector<uint8_t>& buf, const Prefix& prefix) {
    write_uint8(buf, prefix.length);

    int num_bytes = (prefix.length + 7) / 8;
    uint32_t ip = parse_ipv4(prefix.network);

    for (int i = 0; i < num_bytes; i++) {
        write_uint8(buf, (ip >> (24 - i * 8)) & 0xFF);
    }
}

static void encode_path_attributes(vector<uint8_t>& buf, const PathAttributes& attrs) {
    // ORIGIN (type 1)
    write_uint8(buf, 0x40);
    write_uint8(buf, 1);
    write_uint8(buf, 1);
    write_uint8(buf, static_cast<uint8_t>(attrs.origin));

    // AS_PATH (type 2)
    write_uint8(buf, 0x40);
    write_uint8(buf, 2);
    write_uint8(buf, 2 + attrs.as_path.size() * 4);
    write_uint8(buf, 2);    // AS_SEQUENCE
    write_uint8(buf, attrs.as_path.size());
    for (auto asn : attrs.as_path) {
        write_uint32(buf, asn);
    }

    // NEXT_HOP (type 3)
    write_uint8(buf, 0x40);
    write_uint8(buf, 3);
    write_uint8(buf, 4);
    uint32_t nh = parse_ipv4(attrs.next_hop);
    write_uint32(buf, nh);

    // MED (type 4)
    if (attrs.med > 0) {
        write_uint8(buf, 0x80);
        write_uint8(buf, 4);
        write_uint8(buf, 4);
        write_uint32(buf, attrs.med);
    }

    // LOCAL_PREF (type 5)
    write_uint8(buf, 0x40);
    write_uint8(buf, 5);
    write_uint8(buf, 4);
    write_uint32(buf, attrs.local_pref);

    // ATOMIC_AGGREGATE (type 6)
    if (attrs.atomic_aggregate) {
        write_uint8(buf, 0x40);
        write_uint8(buf, 6);
        write_uint8(buf, 0);
    }

    // COMMUNITY (type 8)
    if (!attrs.communities.empty()) {
        write_uint8(buf, 0xC0);
        write_uint8(buf, 8);
        write_uint8(buf, attrs.communities.size() * 4);
        for (auto community : attrs.communities) {
            write_uint32(buf, community);
        }
    }
}


vector<uint8_t> encode_update(const PathAttributes& attrs, const vector<Prefix>& nlri) {
    vector<uint8_t> path_attrs_buf;
    encode_path_attributes(path_attrs_buf, attrs);

    vector<uint8_t> nlri_buf;
    for (auto& prefix : nlri) {
        encode_nlri_prefix(nlri_buf, prefix);
    }

    vector<uint8_t> msg;

    // Marker (16 x 0xFF)
    for (int i = 0; i < 16; i++) msg.push_back(0xFF);

    // Length
    uint16_t total_len = 19 + 2 + 2 + path_attrs_buf.size() + nlri_buf.size();
    write_uint16(msg, total_len);

    // Type: UPDATE
    write_uint8(msg, 2);

    // Withdrawn Routes Length: 0
    write_uint16(msg, 0);

    // Path Attribute Length
    write_uint16(msg, path_attrs_buf.size());

    // Path Attributes
    msg.insert(msg.end(), path_attrs_buf.begin(), path_attrs_buf.end());

    // NLRI
    msg.insert(msg.end(), nlri_buf.begin(), nlri_buf.end());

    return msg;
}

vector<uint8_t> encode_withdraw(const vector<Prefix>& withdrawn) {
    vector<uint8_t> withdrawn_buf;
    for (auto& prefix : withdrawn) {
        encode_nlri_prefix(withdrawn_buf, prefix);
    }

    vector<uint8_t> msg;

    // Marker
    for (int i = 0; i < 16; i++) msg.push_back(0xFF);

    // Length
    uint16_t total_len = 19 + 2 + withdrawn_buf.size() + 2;
    write_uint16(msg, total_len);

    // Type: UPDATE
    write_uint8(msg, 2);

    // Withdrawn Routes Length
    write_uint16(msg, withdrawn_buf.size());

    // Withdrawn Routes
    msg.insert(msg.end(), withdrawn_buf.begin(), withdrawn_buf.end());

    // Path Attribute Length: 0
    write_uint16(msg, 0);

    return msg;
}
