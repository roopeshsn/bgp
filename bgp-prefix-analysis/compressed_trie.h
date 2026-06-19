#ifndef COMPRESSED_TRIE_H
#define COMPRESSED_TRIE_H

#include "bgp_types.h"
#include <functional>
#include <map>

using namespace std;


// Plain binary trie — one node per bit, no compression.
// Used only for comparison stats.
struct PlainTrieNode {
    PlainTrieNode* children[2];
    bool has_route;

    PlainTrieNode() : children{nullptr, nullptr}, has_route(false) {}
};


class CompressedTrie {
public:
    CompressedTrie();
    ~CompressedTrie();

    void insert(const Prefix& prefix, uint32_t attr_index);

    int prefix_count() const;
    int node_count() const;
    int max_depth() const;
    size_t memory_usage() const;

    int plain_trie_node_count() const;
    size_t plain_trie_memory() const;

    void walk(function<void(const Prefix&, uint32_t attr_index)> visitor) const;
    map<int, int> prefix_length_distribution() const;

private:
    TrieNode* root;
    int num_prefixes;
    int num_nodes;
    int deepest;

    // Plain trie for accurate comparison
    PlainTrieNode* plain_root;
    int plain_nodes;
    void plain_insert(const Prefix& prefix);
    void destroy_plain(PlainTrieNode* node);

    int get_bit(uint32_t address, int position) const;
    uint32_t extract_bits(uint32_t address, int start, int count) const;

    void walk_recursive(TrieNode* node, uint32_t address, int depth,
                        function<void(const Prefix&, uint32_t attr_index)>& visitor) const;
    void destroy_recursive(TrieNode* node);
};

#endif
