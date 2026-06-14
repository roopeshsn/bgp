#ifndef BGP_TYPES_H
#define BGP_TYPES_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>

using namespace std;


enum class Origin {
    IGP,
    EGP,
    INCOMPLETE
};

struct Prefix {
    uint32_t network;
    uint8_t length;
};

struct PathAttributes {
    Origin origin;
    vector<uint32_t> as_path;
    uint32_t next_hop;
    uint32_t local_pref;
    uint32_t med;
    vector<uint32_t> communities;
    bool atomic_aggregate;
    uint32_t aggregator_as;
    uint32_t aggregator_ip;

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
        combine(hash<uint32_t>()(pa.next_hop));
        combine(hash<uint32_t>()(pa.local_pref));
        combine(hash<uint32_t>()(pa.med));
        for (uint32_t comm : pa.communities) {
            combine(hash<uint32_t>()(comm));
        }
        combine(hash<bool>()(pa.atomic_aggregate));
        combine(hash<uint32_t>()(pa.aggregator_as));
        combine(hash<uint32_t>()(pa.aggregator_ip));

        return result;
    }
};

struct SharedAttributes {
    PathAttributes attributes;
    uint32_t ref_count;
};

// Compressed trie node — stores a bit range instead of one bit per node.
// skip_bits indicates how many bits this edge covers (the path-compressed segment).
// skip_value holds those bits for verification during lookup.
struct TrieNode {
    TrieNode* children[2];
    bool has_route;
    uint32_t attr_index;

    uint8_t skip_bits;
    uint32_t skip_value;

    TrieNode() : children{nullptr, nullptr}, has_route(false), attr_index(0),
                 skip_bits(0), skip_value(0) {}
};

#endif
