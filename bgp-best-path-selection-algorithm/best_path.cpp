#include "best_path.h"
#include <unordered_map>


// Step 1: Prefer routes with the highest weight.
// Weight is a Cisco-style attribute that is locally significant (not propagated).
// Common use: manually prefer one peer's routes over another's.
vector<CandidatePath> filter_by_weight(const vector<CandidatePath>& candidates) {
    uint32_t highest_weight = 0;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].weight > highest_weight) {
            highest_weight = candidates[i].weight;
        }
    }

    vector<CandidatePath> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].weight == highest_weight) {
            result.push_back(candidates[i]);
        }
    }

    return result;
}

// Step 2: Prefer routes with the highest LOCAL_PREF.
// LOCAL_PREF is shared within an AS to influence outbound traffic.
// Higher value = more preferred. Default is typically 100.
vector<CandidatePath> filter_by_local_pref(const vector<CandidatePath>& candidates) {
    uint32_t highest_local_pref = 0;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].attributes.local_pref > highest_local_pref) {
            highest_local_pref = candidates[i].attributes.local_pref;
        }
    }

    vector<CandidatePath> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].attributes.local_pref == highest_local_pref) {
            result.push_back(candidates[i]);
        }
    }

    return result;
}

// Step 3: Prefer routes that were locally originated.
// Locally originated routes come from network statements, redistribution,
// or aggregation on this router. If any candidate is locally originated,
// all non-local candidates are eliminated.
vector<CandidatePath> filter_by_locally_originated(const vector<CandidatePath>& candidates) {
    bool any_local = false;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].locally_originated) {
            any_local = true;
            break;
        }
    }

    if (!any_local) {
        return candidates;
    }

    vector<CandidatePath> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].locally_originated) {
            result.push_back(candidates[i]);
        }
    }

    return result;
}

// Step 4: Prefer routes with the shortest AS_PATH.
// Fewer AS hops = shorter path through the internet.
// This is the primary inter-AS routing metric.
vector<CandidatePath> filter_by_as_path_length(const vector<CandidatePath>& candidates) {
    size_t shortest_length = candidates[0].attributes.as_path.size();
    for (int i = 1; i < candidates.size(); i++) {
        size_t path_length = candidates[i].attributes.as_path.size();
        if (path_length < shortest_length) {
            shortest_length = path_length;
        }
    }

    vector<CandidatePath> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].attributes.as_path.size() == shortest_length) {
            result.push_back(candidates[i]);
        }
    }

    return result;
}

// Step 5: Prefer routes with the lowest origin type.
// IGP (0) is preferred over EGP (1), which is preferred over INCOMPLETE (2).
// IGP means the route was injected via a network statement.
// INCOMPLETE means the route was redistributed from another protocol.
vector<CandidatePath> filter_by_origin(const vector<CandidatePath>& candidates) {
    int lowest_origin = static_cast<int>(candidates[0].attributes.origin);
    for (int i = 1; i < candidates.size(); i++) {
        int origin_value = static_cast<int>(candidates[i].attributes.origin);
        if (origin_value < lowest_origin) {
            lowest_origin = origin_value;
        }
    }

    vector<CandidatePath> result;
    for (int i = 0; i < candidates.size(); i++) {
        int origin_value = static_cast<int>(candidates[i].attributes.origin);
        if (origin_value == lowest_origin) {
            result.push_back(candidates[i]);
        }
    }

    return result;
}

// Step 6: Prefer routes with the lowest MED (Multi-Exit Discriminator).
// MED is only compared between routes from the SAME neighboring AS.
//
// MED tells a neighbor "if you have multiple links to my AS, prefer this one."
// It would be meaningless to compare MED values from different ASes because
// each AS sets its own MED scale independently.
//
// Algorithm:
//   1. Group candidates by their neighbor AS
//   2. Within each group, keep only the candidate(s) with the lowest MED
//   3. Recombine all group winners
vector<CandidatePath> filter_by_med(const vector<CandidatePath>& candidates) {
    // Group candidates by neighbor AS
    unordered_map<uint32_t, vector<CandidatePath>> groups;
    for (int i = 0; i < candidates.size(); i++) {
        uint32_t neighbor = candidates[i].neighbor_as;
        groups[neighbor].push_back(candidates[i]);
    }

    // Within each neighbor AS group, find the lowest MED and keep only
    // the candidates that match it
    vector<CandidatePath> result;

    for (auto it = groups.begin(); it != groups.end(); it++) {
        vector<CandidatePath>& group = it->second;

        // Find the lowest MED in this group
        uint32_t lowest_med = group[0].attributes.med;
        for (int i = 1; i < group.size(); i++) {
            if (group[i].attributes.med < lowest_med) {
                lowest_med = group[i].attributes.med;
            }
        }

        // Keep only candidates with the lowest MED
        for (int i = 0; i < group.size(); i++) {
            if (group[i].attributes.med == lowest_med) {
                result.push_back(group[i]);
            }
        }
    }

    return result;
}

// Step 7: Prefer eBGP routes over iBGP routes.
// External BGP routes are preferred because they represent direct peering
// relationships, while iBGP routes have already traversed another router
// within the same AS.
vector<CandidatePath> filter_by_peer_type(const vector<CandidatePath>& candidates) {
    bool any_ebgp = false;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].peer_type == PeerType::EBGP) {
            any_ebgp = true;
            break;
        }
    }

    if (!any_ebgp) {
        return candidates;
    }

    vector<CandidatePath> result;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].peer_type == PeerType::EBGP) {
            result.push_back(candidates[i]);
        }
    }

    return result;
}


SelectionResult select_best_path(vector<CandidatePath> candidates) {
    SelectionResult result;

    if (candidates.empty()) {
        result.decisive_step = 0;
        result.decisive_reason = "No candidates";
        return result;
    }

    if (candidates.size() == 1) {
        result.best = candidates[0];
        result.decisive_step = 0;
        result.decisive_reason = "Only one candidate";
        return result;
    }

    // Step 1: Highest Weight
    vector<CandidatePath> remaining = filter_by_weight(candidates);
    if (remaining.size() == 1) {
        result.best = remaining[0];
        result.decisive_step = 1;
        result.decisive_reason = "Highest weight (" + to_string(remaining[0].weight) + ")";
        return result;
    }

    // Step 2: Highest LOCAL_PREF
    remaining = filter_by_local_pref(remaining);
    if (remaining.size() == 1) {
        result.best = remaining[0];
        result.decisive_step = 2;
        result.decisive_reason = "Highest LOCAL_PREF (" + to_string(remaining[0].attributes.local_pref) + ")";
        return result;
    }

    // Step 3: Prefer locally originated
    size_t before_step3 = remaining.size();
    remaining = filter_by_locally_originated(remaining);
    if (remaining.size() == 1) {
        result.best = remaining[0];
        result.decisive_step = 3;
        result.decisive_reason = "Locally originated route preferred";
        return result;
    }

    // Step 4: Shortest AS_PATH
    remaining = filter_by_as_path_length(remaining);
    if (remaining.size() == 1) {
        result.best = remaining[0];
        result.decisive_step = 4;
        result.decisive_reason = "Shortest AS_PATH (length " + to_string(remaining[0].attributes.as_path.size()) + ")";
        return result;
    }

    // Step 5: Lowest Origin type
    remaining = filter_by_origin(remaining);
    if (remaining.size() == 1) {
        result.best = remaining[0];
        result.decisive_step = 5;
        result.decisive_reason = "Lowest origin type";
        return result;
    }

    // Step 6: Lowest MED (same neighbor AS only)
    size_t before_step6 = remaining.size();
    remaining = filter_by_med(remaining);
    if (remaining.size() == 1) {
        result.best = remaining[0];
        result.decisive_step = 6;
        result.decisive_reason = "Lowest MED (" + to_string(remaining[0].attributes.med) + ") among routes from AS " + to_string(remaining[0].neighbor_as);
        return result;
    }

    // Step 7: Prefer eBGP over iBGP
    size_t before_step7 = remaining.size();
    remaining = filter_by_peer_type(remaining);
    if (remaining.size() == 1) {
        result.best = remaining[0];
        result.decisive_step = 7;
        result.decisive_reason = "eBGP preferred over iBGP";
        return result;
    }

    // If we still have multiple candidates after all 7 steps,
    // pick the first one. Steps 8-11 (IGP metric, route age,
    // router ID, neighbor IP) are not implemented.
    result.best = remaining[0];
    result.decisive_step = 7;
    result.decisive_reason = "Tie after all steps — first remaining candidate selected "
                             "(steps 8-11 not implemented: IGP metric, route age, router ID, neighbor IP)";
    return result;
}


BackupSelectionResult select_best_and_backup_path(vector<CandidatePath> candidates) {
    BackupSelectionResult result;

    // First, find the best path using the standard algorithm
    result.best = select_best_path(candidates);

    // If there were 0 or 1 candidates, there's no backup path
    if (candidates.size() <= 1) {
        result.has_backup = false;
        return result;
    }

    // Remove the best path from the candidate list.
    // We identify it by peer_ip since each peer advertises at most one
    // path for a given prefix.
    vector<CandidatePath> remaining_candidates;
    for (int i = 0; i < candidates.size(); i++) {
        if (candidates[i].peer_ip != result.best.best.peer_ip) {
            remaining_candidates.push_back(candidates[i]);
        }
    }

    // Run the algorithm again on the remaining candidates
    if (remaining_candidates.empty()) {
        result.has_backup = false;
        return result;
    }

    result.backup = select_best_path(remaining_candidates);
    result.has_backup = true;
    return result;
}
