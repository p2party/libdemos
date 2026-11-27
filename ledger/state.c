#include "demos_ledger_state.h"
#include "tagged.h"

#include <stdlib.h>

#define WIDTH DEMOS_STATE_BYTES
#define DEPTH (8u * WIDTH)
#define BITMAP_OFFSET (6u + WIDTH)
typedef uint8_t digest[WIDTH];

/* Only occupied leaves and branching nodes are materialized. Each edge
   stores the child's full subtree digest immediately below the branch. */
typedef struct node
{
  digest key, hash;
  unsigned depth;
  struct node *children[2];
  digest edges[2];
} node;

typedef struct
{
  digest at[DEPTH + 1];
} empty_hashes;
struct demos_state
{
  empty_hashes empty;
  node *top;
  digest root;
};

static int
claim_key(enum demos_state_kind kind, const uint8_t *id, digest out)
{
  const char *tag;
  switch (kind)
  {
  case DEMOS_STATE_SPENT:
    tag = "smt/spent";
    break;
  case DEMOS_STATE_MOVE:
    tag = "smt/move";
    break;
  case DEMOS_STATE_OWNER:
    tag = "smt/owner";
    break;
  default:
    return 0;
  }
  if (!id) return 0;
  tagged_hash(tag, id, WIDTH, out);
  return 1;
}

static unsigned
bit(const uint8_t *key, unsigned depth)
{
  return (key[depth / 8] >> (7 - depth % 8)) & 1u;
}

static void
branch_hash(const uint8_t *left, const uint8_t *right, digest out)
{
  uint8_t pair[WIDTH * 2];
  memcpy(pair, left, WIDTH);
  memcpy(pair + WIDTH, right, WIDTH);
  tagged_hash("smt/node", pair, sizeof(pair), out);
}

static void
initialize_empty(empty_hashes *empty)
{
  tagged_hash("smt/empty", (const uint8_t *)"", 0, empty->at[DEPTH]);
  for (unsigned d = DEPTH; d > 0; --d)
    branch_hash(empty->at[d], empty->at[d], empty->at[d - 1]);
}

static void
join_path(unsigned direction, digest value, const uint8_t *sibling)
{
  if (direction == 0) branch_hash(value, sibling, value);
  else
    branch_hash(sibling, value, value);
}

static void
subtree_hash(const node *n, unsigned at, const empty_hashes *empty, digest out)
{
  memcpy(out, n->hash, WIDTH);
  for (unsigned d = n->depth; d > at; --d)
    join_path(bit(n->key, d - 1), out, empty->at[d]);
}

static unsigned
shared_prefix(const uint8_t *a, const uint8_t *b, unsigned from, unsigned end)
{
  while (from < end && bit(a, from) == bit(b, from))
    ++from;
  return from;
}

static node *
new_leaf(const digest key)
{
  node *n = calloc(1, sizeof(*n));
  if (!n) return NULL;
  n->depth = DEPTH;
  memcpy(n->key, key, WIDTH);
  tagged_hash("smt/leaf", key, WIDTH, n->hash);
  return n;
}

static int
insert_at(node **slot, unsigned from, const digest key,
          const empty_hashes *empty)
{
  node *n = *slot;
  if (!n)
  {
    *slot = new_leaf(key);
    return *slot != NULL;
  }
  unsigned d = shared_prefix(key, n->key, from, n->depth);
  if (d == DEPTH) return 0;
  unsigned side = bit(key, d);
  if (d < n->depth)
  {
    node *parent = calloc(1, sizeof(*parent));
    if (!parent) return 0;
    parent->children[side] = new_leaf(key);
    if (!parent->children[side])
    {
      free(parent);
      return 0;
    }
    parent->children[1 - side] = n;
    memcpy(parent->key, key, WIDTH);
    parent->depth = d;
    subtree_hash(n, d + 1, empty, parent->edges[1 - side]);
    *slot = n = parent;
  }
  else if (!insert_at(&n->children[side], d + 1, key, empty))
  {
    return 0;
  }
  subtree_hash(n->children[side], d + 1, empty, n->edges[side]);
  branch_hash(n->edges[0], n->edges[1], n->hash);
  return 1;
}

demos_state *
demos_state_new(void)
{
  demos_state *tree = calloc(1, sizeof(*tree));
  if (tree)
  {
    initialize_empty(&tree->empty);
    memcpy(tree->root, tree->empty.at[0], WIDTH);
  }
  return tree;
}

static void
free_node(node *n)
{
  if (!n) return;
  free_node(n->children[0]);
  free_node(n->children[1]);
  free(n);
}

void
demos_state_free(demos_state *tree)
{
  if (tree)
  {
    free_node(tree->top);
    free(tree);
  }
}

int
demos_state_insert(demos_state *tree, enum demos_state_kind kind,
                   const uint8_t id[64])
{
  digest key;
  if (!tree || !claim_key(kind, id, key)
      || !insert_at(&tree->top, 0, key, &tree->empty))
    return 0;
  subtree_hash(tree->top, 0, &tree->empty, tree->root);
  return 1;
}

int
demos_state_root(const demos_state *tree, uint8_t root[64])
{
  if (!tree || !root) return 0;
  memcpy(root, tree->root, WIDTH);
  return 1;
}

int
demos_state_prove(const demos_state *tree, enum demos_state_kind kind,
                  const uint8_t id[64], uint8_t *proof, size_t capacity,
                  size_t *size)
{
  digest key;
  if (!tree || !proof || !size || capacity < DEMOS_STATE_PROOF_HEADER
      || !claim_key(kind, id, key))
    return 0;
  size_t used = DEMOS_STATE_PROOF_HEADER;
  memcpy(proof, "DSS1", 4);
  proof[4] = (uint8_t)kind;
  proof[5] = 0;
  memcpy(proof + 6, id, WIDTH);
  uint8_t *bitmap = proof + BITMAP_OFFSET;
  memset(bitmap, 0, WIDTH);
  unsigned from = 0;
  for (const node *n = tree->top; n;)
  {
    unsigned d = shared_prefix(key, n->key, from, n->depth);
    if (d == DEPTH)
    {
      proof[5] = 1;
      break;
    }
    if (capacity - used < WIDTH) return 0;
    bitmap[d / 8] |= (uint8_t)(0x80u >> (d % 8));
    if (d < n->depth)
    {
      subtree_hash(n, d + 1, &tree->empty, proof + used);
      used += WIDTH;
      break;
    }
    unsigned side = bit(key, d);
    memcpy(proof + used, n->edges[1 - side], WIDTH);
    used += WIDTH;
    from = d + 1;
    n = n->children[side];
  }
  *size = used;
  return 1;
}

static int
verify_or_insert(const uint8_t root[64], enum demos_state_kind kind,
                 const uint8_t id[64], int present, const uint8_t *proof,
                 size_t size, uint8_t *next_root)
{
  digest key;
  if (!root || !proof || (present != 0 && present != 1)
      || size < DEMOS_STATE_PROOF_HEADER || size > DEMOS_STATE_MAX_PROOF
      || (size - DEMOS_STATE_PROOF_HEADER) % WIDTH != 0
      || !claim_key(kind, id, key) || memcmp(proof, "DSS1", 4)
      || proof[4] != kind || proof[5] != present
      || memcmp(proof + 6, id, WIDTH))
    return 0;

  empty_hashes empty;
  initialize_empty(&empty);
  digest value, occupied;
  if (present) tagged_hash("smt/leaf", key, WIDTH, value);
  else
    memcpy(value, empty.at[DEPTH], WIDTH);
  if (next_root) tagged_hash("smt/leaf", key, WIDTH, occupied);
  size_t offset = size;
  for (unsigned d = DEPTH; d > 0; --d)
  {
    const uint8_t *sibling = empty.at[d];
    if (bit(proof + BITMAP_OFFSET, d - 1))
    {
      if (offset - DEMOS_STATE_PROOF_HEADER < WIDTH) return 0;
      offset -= WIDTH;
      sibling = proof + offset;
      if (memcmp(sibling, empty.at[d], WIDTH) == 0) return 0;
    }
    unsigned direction = bit(key, d - 1);
    join_path(direction, value, sibling);
    if (next_root) join_path(direction, occupied, sibling);
  }
  if (offset != DEMOS_STATE_PROOF_HEADER || memcmp(value, root, WIDTH))
    return 0;
  if (next_root) memcpy(next_root, occupied, WIDTH);
  return 1;
}

int
demos_state_verify(const uint8_t root[64], enum demos_state_kind kind,
                   const uint8_t id[64], int present, const uint8_t *proof,
                   size_t size)
{
  return verify_or_insert(root, kind, id, present, proof, size, NULL);
}

int
demos_state_insert_root(const uint8_t root[64], enum demos_state_kind kind,
                        const uint8_t id[64], const uint8_t *proof, size_t size,
                        uint8_t next_root[64])
{
  if (!next_root) return 0;
  return verify_or_insert(root, kind, id, 0, proof, size, next_root);
}
