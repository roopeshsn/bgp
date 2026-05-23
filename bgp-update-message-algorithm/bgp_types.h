#ifndef BGP_TYPES_H
#define BGP_TYPES_H

#include <string>
#include <vector>
#include <cstdint>

using namespace std;

enum class Origin {
    IGP,
    EGP,
    INCOMPLETE
};

struct Prefix {
    string network;
    uint8_t length;
};

struct PathAttributes {
    Origin origin;
    vector<uint32_t> as_path;
    string next_hop;
    uint32_t local_pref;
    uint32_t med;
    vector<uint32_t> communities;
    bool atomic_aggregate;
    uint32_t aggregator_as;
    string aggregator_ip;

    bool operator==(const PathAttributes& other) const {
        return origin == other.origin
            && as_path == other.as_path
            && next_hop == other.next_hop
            && local_pref == other.local_pref
            && med == other.med
            && communities == other.communities
            && atomic_aggregate == other.atomic_aggregate
            && aggregator_as == other.aggregator_as
            && aggregator_ip == other.aggregator_ip;
    }
};

struct PathAttributesHash {
    size_t operator()(const PathAttributes& pa) const {
        size_t result = 0;

        auto combine = [&result](size_t value) {
            result ^= value + 0x9e3779b9 + (result << 6) + (result >> 2);
        };

        combine(hash<int>()(static_cast<int>(pa.origin)));
        for (uint32_t asn : pa.as_path) {
            combine(hash<uint32_t>()(asn));
        }
        combine(hash<string>()(pa.next_hop));
        combine(hash<uint32_t>()(pa.local_pref));
        combine(hash<uint32_t>()(pa.med));
        for (uint32_t comm : pa.communities) {
            combine(hash<uint32_t>()(comm));
        }
        combine(hash<bool>()(pa.atomic_aggregate));
        combine(hash<uint32_t>()(pa.aggregator_as));
        combine(hash<string>()(pa.aggregator_ip));

        return result;
    }
};

struct Route {
    Prefix prefix;
    PathAttributes attributes;
};

struct BGPUpdateMessage {
    PathAttributes attributes;
    vector<Prefix> nlri;
    size_t message_size;
};

const size_t BGP_MAX_MESSAGE_SIZE = 4096;
const size_t BGP_HEADER_SIZE = 19;
const size_t BGP_WITHDRAWN_LENGTH_FIELD = 2;
const size_t BGP_PATH_ATTR_LENGTH_FIELD = 2;

#endif
