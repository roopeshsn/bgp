# BGP Prefix Analysis

## Getting Started

### To compile and run:

```
g++ -std=c++17 -lz -o bgp_prefix_analysis main.cpp mrt_parser.cpp compressed_trie.cpp prefix_analysis.cpp
```

```
./bgp_prefix_analysis latest-bview.gz
```

### Where to download the BRIB file?

RIPE RIS: https://ris.ripe.net/docs/route-collectors/
RRC00: https://data.ris.ripe.net/rrc00/

### How a MRT dump file looks like?

Each prefix will be represented as a MRT record.

MRT parsers like bgpkit-parser can be used to read a MRT file.

```
bgpkit-parser ./latest-bview.gz -r
bgpkit-parser ./latest-bview.gz -p 0.0.0.0/0
```

Read RFC 6396: https://datatracker.ietf.org/doc/html/rfc6396
