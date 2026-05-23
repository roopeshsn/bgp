#ifndef PACKET_ENCODER_H
#define PACKET_ENCODER_H

#include "bgp_types.h"

// Encode a BGPUpdateMessage into raw BGP wire-format bytes (RFC 4271)
vector<uint8_t> encode_bgp_update(const BGPUpdateMessage& msg);

// Build a complete network packet (Ethernet + IP + TCP + BGP) from BGP bytes
vector<uint8_t> build_packet(const vector<uint8_t>& bgp_bytes, uint32_t tcp_seq_num);

// Write a list of packets to a .pcap file that Wireshark can open
void write_pcap_file(const string& filename, const vector<vector<uint8_t>>& packets);

#endif
