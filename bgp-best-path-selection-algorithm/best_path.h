#ifndef BEST_PATH_H
#define BEST_PATH_H

#include "bgp_types.h"

// Run the BGP best path selection algorithm (Steps 1-7) on a set of
// candidate paths for the same prefix. Returns the winning path and
// which step was decisive.
//
// Steps applied in order:
//   1. Highest Weight
//   2. Highest LOCAL_PREF
//   3. Prefer locally originated routes
//   4. Shortest AS_PATH
//   5. Lowest Origin type (IGP < EGP < INCOMPLETE)
//   6. Lowest MED (only among routes from same neighboring AS)
//   7. Prefer eBGP over iBGP
SelectionResult select_best_path(vector<CandidatePath> candidates);

// Select both the best path and the backup (second-best) path.
// Works by running the best path algorithm, removing the winner from the
// candidate list, then running the algorithm again on the remaining candidates
// to find the second-best path.
BackupSelectionResult select_best_and_backup_path(vector<CandidatePath> candidates);

#endif
