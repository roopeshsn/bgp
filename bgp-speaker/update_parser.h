#ifndef UPDATE_PARSER_H
#define UPDATE_PARSER_H

#include "bgp_types.h"

bool parse_update(const uint8_t* data, uint16_t length, ParsedUpdate& result);

#endif
