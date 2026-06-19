#include "compressed_trie.h"

using namespace std;


CompressedTrie::CompressedTrie()
    : num_prefixes(0), num_nodes(1), deepest(0), plain_nodes(1) {
    root = new TrieNode();
    plain_root = new PlainTrieNode();
}

CompressedTrie::~CompressedTrie() {
    destroy_recursive(root);
    destroy_plain(plain_root);
}

void CompressedTrie::destroy_plain(PlainTrieNode* node) {
    if (!node) return;
    destroy_plain(node->children[0]);
    destroy_plain(node->children[1]);
    delete node;
}

void CompressedTrie::plain_insert(const Prefix& prefix) {
    PlainTrieNode* current = plain_root;

    for (int i = 0; i < prefix.length; i++) {
        int bit = get_bit(prefix.network, i);

        if (!current->children[bit]) {
            current->children[bit] = new PlainTrieNode();
            plain_nodes++;
        }

        current = current->children[bit];
    }

    current->has_route = true;
}

void CompressedTrie::destroy_recursive(TrieNode* node) {
    if (!node) return;
    destroy_recursive(node->children[0]);
    destroy_recursive(node->children[1]);
    delete node;
}

int CompressedTrie::get_bit(uint32_t address, int position) const {
    return (address >> (31 - position)) & 1;
}

uint32_t CompressedTrie::extract_bits(uint32_t address, int start, int count) const {
    if (count == 0) return 0;
    return (address >> (32 - start - count)) & ((1 << count) - 1);
}


void CompressedTrie::insert(const Prefix& prefix, uint32_t attr_index) {
    plain_insert(prefix);

    if (!root->has_route && !root->children[0] && !root->children[1]) {
        // Empty trie — store directly at root if prefix length is 0,
        // otherwise create the first path
        if (prefix.length == 0) {
            root->has_route = true;
            root->attr_index = attr_index;
            num_prefixes++;
            return;
        }
    }

    TrieNode* current = root;
    int bit_pos = 0;

    while (bit_pos < prefix.length) {
        int bit = get_bit(prefix.network, bit_pos);

        if (!current->children[bit]) {
            // No child — create a new leaf with the remaining bits compressed
            TrieNode* leaf = new TrieNode();
            int remaining = prefix.length - bit_pos - 1;
            leaf->skip_bits = remaining;
            if (remaining > 0) {
                leaf->skip_value = extract_bits(prefix.network, bit_pos + 1, remaining);
            }
            leaf->has_route = true;
            leaf->attr_index = attr_index;
            current->children[bit] = leaf;
            num_nodes++;
            num_prefixes++;

            if (prefix.length > deepest) {
                deepest = prefix.length;
            }
            return;
        }

        TrieNode* child = current->children[bit];
        bit_pos++;

        // Check if the compressed path matches
        if (child->skip_bits > 0) {
            int skip = child->skip_bits;
            int remaining_prefix = prefix.length - bit_pos;

            // Compare the skip segment bit by bit
            int match_len = 0;
            int compare_len = (skip < remaining_prefix) ? skip : remaining_prefix;

            uint32_t child_skip = child->skip_value;
            uint32_t prefix_segment = 0;
            if (compare_len > 0) {
                prefix_segment = extract_bits(prefix.network, bit_pos, compare_len);
                uint32_t child_segment = child_skip >> (skip - compare_len);

                // Find where they diverge
                for (int i = 0; i < compare_len; i++) {
                    int child_bit = (child_skip >> (skip - 1 - i)) & 1;
                    int prefix_bit = 0;
                    if (bit_pos + i < 32) {
                        prefix_bit = get_bit(prefix.network, bit_pos + i);
                    }
                    if (child_bit != prefix_bit) break;
                    match_len++;
                }
            }

            if (match_len == skip && remaining_prefix == skip) {
                // Exact match — prefix ends at this node
                if (!child->has_route) {
                    num_prefixes++;
                }
                child->has_route = true;
                child->attr_index = attr_index;

                if (prefix.length > deepest) {
                    deepest = prefix.length;
                }
                return;
            }

            if (match_len == skip) {
                // Full skip matched but prefix is longer — continue from child
                bit_pos += skip;
                current = child;
                continue;
            }

            if (match_len == remaining_prefix && remaining_prefix < skip) {
                // Prefix ends in the middle of the skip — split the node
                TrieNode* mid = new TrieNode();
                mid->skip_bits = match_len;
                if (match_len > 0) {
                    mid->skip_value = extract_bits(prefix.network, bit_pos, match_len);
                }
                mid->has_route = true;
                mid->attr_index = attr_index;

                // Adjust existing child to continue after the split
                int old_remaining = skip - match_len - 1;
                int diverge_bit = (child->skip_value >> (skip - match_len - 1)) & 1;

                child->skip_bits = old_remaining;
                if (old_remaining > 0) {
                    child->skip_value = child->skip_value & ((1 << old_remaining) - 1);
                } else {
                    child->skip_value = 0;
                }

                mid->children[diverge_bit] = child;
                current->children[bit - 1 + 1] = mid;  // same slot
                // Fix: use the correct slot
                current->children[bit] = mid;

                num_nodes++;
                num_prefixes++;

                if (prefix.length > deepest) {
                    deepest = prefix.length;
                }
                return;
            }

            // Divergence in the middle — split at the divergence point
            TrieNode* mid = new TrieNode();
            mid->skip_bits = match_len;
            if (match_len > 0) {
                mid->skip_value = extract_bits(prefix.network, bit_pos, match_len);
            }

            // Existing child continues on one side
            int old_diverge_bit = (child->skip_value >> (skip - match_len - 1)) & 1;
            int old_remaining = skip - match_len - 1;
            child->skip_bits = old_remaining;
            if (old_remaining > 0) {
                child->skip_value = child->skip_value & ((1 << old_remaining) - 1);
            } else {
                child->skip_value = 0;
            }
            mid->children[old_diverge_bit] = child;

            // New prefix goes on the other side
            int new_diverge_bit = get_bit(prefix.network, bit_pos + match_len);
            int new_remaining = prefix.length - bit_pos - match_len - 1;

            TrieNode* new_leaf = new TrieNode();
            new_leaf->skip_bits = new_remaining;
            if (new_remaining > 0) {
                new_leaf->skip_value = extract_bits(prefix.network,
                    bit_pos + match_len + 1, new_remaining);
            }
            new_leaf->has_route = true;
            new_leaf->attr_index = attr_index;

            mid->children[new_diverge_bit] = new_leaf;
            current->children[bit] = mid;

            num_nodes += 2;
            num_prefixes++;

            if (prefix.length > deepest) {
                deepest = prefix.length;
            }
            return;
        }

        // No skip bits on this child — it's a branching node, continue
        current = child;
    }

    // We've consumed all bits — mark current node
    if (!current->has_route) {
        num_prefixes++;
    }
    current->has_route = true;
    current->attr_index = attr_index;

    if (prefix.length > deepest) {
        deepest = prefix.length;
    }
}


int CompressedTrie::prefix_count() const {
    return num_prefixes;
}

int CompressedTrie::node_count() const {
    return num_nodes;
}

int CompressedTrie::max_depth() const {
    return deepest;
}

size_t CompressedTrie::memory_usage() const {
    return (size_t)num_nodes * sizeof(TrieNode);
}

int CompressedTrie::plain_trie_node_count() const {
    return plain_nodes;
}

size_t CompressedTrie::plain_trie_memory() const {
    return (size_t)plain_nodes * sizeof(PlainTrieNode);
}


map<int, int> CompressedTrie::prefix_length_distribution() const {
    map<int, int> distribution;
    function<void(const Prefix&, uint32_t)> counter = [&](const Prefix& p, uint32_t) {
        distribution[p.length]++;
    };
    walk_recursive(root, 0, 0, counter);
    return distribution;
}

void CompressedTrie::walk(function<void(const Prefix&, uint32_t attr_index)> visitor) const {
    walk_recursive(root, 0, 0, visitor);
}

void CompressedTrie::walk_recursive(TrieNode* node, uint32_t address, int depth,
                                   function<void(const Prefix&, uint32_t attr_index)>& visitor) const {
    if (!node) return;

    if (node->has_route) {
        Prefix prefix;
        prefix.network = address;
        prefix.length = depth;
        visitor(prefix, node->attr_index);
    }

    for (int bit = 0; bit <= 1; bit++) {
        if (node->children[bit]) {
            TrieNode* child = node->children[bit];

            uint32_t child_addr = address;
            int child_depth = depth;

            // Set the branching bit
            if (bit == 1) {
                child_addr |= (1 << (31 - depth));
            }
            child_depth++;

            // Apply the skip bits
            for (int s = 0; s < child->skip_bits; s++) {
                int skip_bit = (child->skip_value >> (child->skip_bits - 1 - s)) & 1;
                if (skip_bit) {
                    child_addr |= (1 << (31 - child_depth));
                }
                child_depth++;
            }

            walk_recursive(child, child_addr, child_depth, visitor);
        }
    }
}
