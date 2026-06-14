#ifndef MRT_PARSER_H
#define MRT_PARSER_H

#include "bgp_types.h"
#include <string>
#include <vector>
#include <functional>
#include <zlib.h>

using namespace std;


struct PeerEntry {
    uint8_t peer_type;
    uint32_t peer_bgp_id;
    uint32_t peer_ip;
    uint32_t peer_as;
};

struct MrtHeader {
    uint32_t timestamp;
    uint16_t type;
    uint16_t subtype;
    uint32_t length;
};

// MRT type and subtype constants
const uint16_t MRT_TABLE_DUMP_V2 = 13;
const uint16_t MRT_SUBTYPE_PEER_INDEX_TABLE = 1;
const uint16_t MRT_SUBTYPE_RIB_IPV4_UNICAST = 2;

// BGP path attribute type codes
const uint8_t ATTR_ORIGIN = 1;
const uint8_t ATTR_AS_PATH = 2;
const uint8_t ATTR_NEXT_HOP = 3;
const uint8_t ATTR_MED = 4;
const uint8_t ATTR_LOCAL_PREF = 5;
const uint8_t ATTR_ATOMIC_AGGREGATE = 6;
const uint8_t ATTR_AGGREGATOR = 7;
const uint8_t ATTR_COMMUNITY = 8;

// AS_PATH segment types
const uint8_t AS_SET = 1;
const uint8_t AS_SEQUENCE = 2;


class MrtParser {
public:
    MrtParser();

    bool open(const string& filename);
    void close();

    int parse_rib_dump(function<void(const Prefix&, const PathAttributes&, uint16_t peer_index)> on_route);

    int get_peer_count() const;
    int get_record_count() const;
    const PeerEntry& get_peer(uint16_t index) const;
    const vector<PeerEntry>& get_peer_table() const;

private:
    gzFile file;
    vector<PeerEntry> peer_table;
    int record_count;

    bool read_bytes(uint8_t* buffer, int length);
    uint16_t read_uint16(const uint8_t* buf);
    uint32_t read_uint32(const uint8_t* buf);

    bool parse_common_header(MrtHeader& header);
    bool parse_peer_index_table(const uint8_t* data, uint32_t length);
    int parse_rib_ipv4_unicast(const uint8_t* data, uint32_t length,
                                function<void(const Prefix&, const PathAttributes&, uint16_t peer_index)>& on_route);

    PathAttributes parse_bgp_attributes(const uint8_t* data, uint16_t length);
};

#endif
