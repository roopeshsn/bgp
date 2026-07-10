#ifndef UPDATE_ENCODER_H
#define UPDATE_ENCODER_H

#include "bgp_types.h"
#include <vector>

using namespace std;

vector<uint8_t> encode_update(const PathAttributes& attrs, const vector<Prefix>& nlri);
vector<uint8_t> encode_withdraw(const vector<Prefix>& withdrawn);

#endif
