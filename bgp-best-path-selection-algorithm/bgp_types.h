#ifndef BGP_TYPES_H
#define BGP_TYPES_H

#include <string>
#include <vector>
#include <cstdint>

using namespace std;


// Origin attribute values (RFC 4271 Section 4.3)
// IGP: route learned via interior gateway protocol (network statement)
// EGP: route learned via exterior gateway protocol (deprecated)
// INCOMPLETE: route redistributed from another source
enum class Origin {
    IGP,
    EGP,
    INCOMPLETE
};

// Whether the route was learned from an external or internal BGP peer
enum class PeerType {
    EBGP,
    IBGP
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
    bool atomic_aggregate;
};

// A candidate path represents a single route advertisement received from a peer.
// Multiple candidate paths can exist for the same prefix, each learned from a
// different BGP peer. The best path selection algorithm picks the best one.
struct CandidatePath {
    Prefix prefix;
    PathAttributes attributes;

    // Step 1: Weight — Cisco-style local preference (not propagated to peers).
    // Higher is better. Default: 0 for learned routes, 32768 for locally originated.
    uint32_t weight;

    // Step 7: eBGP routes are preferred over iBGP routes.
    PeerType peer_type;

    // The AS number of the neighbor that advertised this route to us.
    // Used in Step 6 (MED comparison) — MED is only compared between routes
    // from the same neighboring AS.
    uint32_t neighbor_as;

    // Step 3: Routes originated by the local router (via network statement,
    // redistribution, or aggregation) are preferred over learned routes.
    bool locally_originated;

    // IP address of the peer that advertised this route.
    string peer_ip;
};

// The result of running the best path selection algorithm on a set of candidates.
struct SelectionResult {
    CandidatePath best;
    int decisive_step;       // which step (1-7) made the final decision
    string decisive_reason;  // human-readable explanation
};

// The result of selecting both a best path and a backup (second-best) path.
// The backup path is the path that would be chosen if the best path were unavailable.
// This is useful for fast failover — if the best path goes down, the router can
// immediately switch to the backup without re-running the full decision process.
struct BackupSelectionResult {
    SelectionResult best;
    SelectionResult backup;
    bool has_backup;         // false if there was only one candidate (no backup possible)
};

#endif
