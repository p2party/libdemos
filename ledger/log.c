#include "demos_ledger_log.h"

#include <sodium/crypto_hash_sha512.h>
#include <string.h>

#define H DEMOS_LOG_HASH_BYTES
_Static_assert(H == crypto_hash_sha512_BYTES, "ledger log requires SHA-512");
_Static_assert(SIZE_MAX <= UINT64_MAX, "proof buffers cover 64-bit tree sizes");

static void
leaf_hash(const uint8_t id[H], uint8_t out[H])
{
  uint8_t input[1 + H] = { 0 };
  memcpy(input + 1, id, H);
  crypto_hash_sha512(out, input, sizeof input);
}

static void
node_hash(const uint8_t left[H], const uint8_t right[H], uint8_t out[H])
{
  uint8_t input[1 + H + H];
  input[0] = 1;
  memcpy(input + 1, left, H);
  memcpy(input + 1 + H, right, H);
  crypto_hash_sha512(out, input, sizeof input);
}

/* Largest power of two strictly below n, for n >= 2. */
static size_t
split(size_t n)
{
  size_t k = 1;
  while (k <= (n - 1) / 2)
    k *= 2;
  return k;
}

static int
valid_input(const uint8_t *ids, size_t count)
{
  return (ids != NULL || count == 0) && count <= (size_t)PTRDIFF_MAX / H;
}

static void
tree_hash(const uint8_t *ids, size_t count, uint8_t out[H])
{
  if (count == 0)
  {
    crypto_hash_sha512(out, (const uint8_t *)"", 0);
  }
  else if (count == 1)
  {
    leaf_hash(ids, out);
  }
  else
  {
    size_t k = split(count);
    uint8_t left[H], right[H];
    tree_hash(ids, k, left);
    tree_hash(ids + k * H, count - k, right);
    node_hash(left, right, out);
  }
}

int
demos_log_root(const uint8_t *ids, size_t count, uint8_t root[H])
{
  if (!root || !valid_input(ids, count)) return 0;
  tree_hash(ids, count, root);
  return 1;
}

static void
inclusion_path(const uint8_t *ids, size_t n, size_t index, demos_log_proof *out)
{
  if (n == 1) return;
  size_t k = split(n);
  if (index < k)
  {
    inclusion_path(ids, k, index, out);
    tree_hash(ids + k * H, n - k, out->nodes[out->count++]);
  }
  else
  {
    inclusion_path(ids + k * H, n - k, index - k, out);
    tree_hash(ids, k, out->nodes[out->count++]);
  }
}

int
demos_log_inclusion_proof(const uint8_t *ids, size_t count, uint64_t index,
                          demos_log_proof *proof)
{
  if (!proof || !valid_input(ids, count) || index >= count) return 0;
  proof->count = 0;
  inclusion_path(ids, count, (size_t)index, proof);
  return 1;
}

/* The original old root starts as known. When the old prefix crosses a split,
   the overlapping right subtree must supply its own starting hash. */
static void
consistency_path(const uint8_t *ids, size_t n, size_t old, int known,
                 demos_log_proof *out)
{
  if (old == n)
  {
    if (!known) tree_hash(ids, n, out->nodes[out->count++]);
    return;
  }
  size_t k = split(n);
  if (old <= k)
  {
    consistency_path(ids, k, old, known, out);
    tree_hash(ids + k * H, n - k, out->nodes[out->count++]);
  }
  else
  {
    consistency_path(ids + k * H, n - k, old - k, 0, out);
    tree_hash(ids, k, out->nodes[out->count++]);
  }
}

int
demos_log_consistency_proof(const uint8_t *ids, size_t count, uint64_t old_size,
                            demos_log_proof *proof)
{
  if (!proof || !valid_input(ids, count) || old_size > count) return 0;
  proof->count = 0;
  if (old_size != 0) consistency_path(ids, count, (size_t)old_size, 1, proof);
  return 1;
}

/* Advance past levels without a right sibling at the unbalanced edge. */
static void
ascend_unpaired(uint64_t *position, uint64_t *last)
{
  while (*position != 0 && (*position & 1) == 0)
  {
    *position >>= 1;
    *last >>= 1;
  }
}

int
demos_log_verify_inclusion(uint64_t size, uint64_t index, const uint8_t id[H],
                           const uint8_t root[H], const demos_log_proof *proof)
{
  if (index >= size || !id || !root || !proof
      || proof->count > DEMOS_LOG_MAX_PROOF_NODES)
    return 0;
  uint64_t last = size - 1;
  uint8_t current[H];
  leaf_hash(id, current);
  for (size_t i = 0; i < proof->count; ++i)
  {
    if (last == 0) return 0;
    if ((index & 1) || index == last)
    {
      node_hash(proof->nodes[i], current, current);
      ascend_unpaired(&index, &last);
    }
    else
    {
      node_hash(current, proof->nodes[i], current);
    }
    index >>= 1;
    last >>= 1;
  }
  return last == 0 && memcmp(current, root, H) == 0;
}

int
demos_log_verify_consistency(uint64_t old_size, uint64_t new_size,
                             const uint8_t old_root[H],
                             const uint8_t new_root[H],
                             const demos_log_proof *proof)
{
  if (old_size > new_size || !old_root || !new_root || !proof
      || proof->count > DEMOS_LOG_MAX_PROOF_NODES)
    return 0;
  if (old_size == 0)
  {
    uint8_t empty[H];
    tree_hash(NULL, 0, empty);
    return proof->count == 0 && memcmp(old_root, empty, H) == 0
           && (new_size > 0 || memcmp(new_root, empty, H) == 0);
  }
  if (old_size == new_size)
    return proof->count == 0 && memcmp(old_root, new_root, H) == 0;
  uint64_t first = old_size - 1, last = new_size - 1;
  while (first & 1)
  {
    first >>= 1;
    last >>= 1;
  }
  size_t i = 0;
  uint8_t old_hash[H], new_hash[H];
  if (first == 0)
  {
    memcpy(old_hash, old_root, H);
  }
  else
  {
    if (proof->count == 0) return 0;
    memcpy(old_hash, proof->nodes[i++], H);
  }
  memcpy(new_hash, old_hash, H);
  for (; i < proof->count; ++i)
  {
    if (last == 0) return 0;
    if ((first & 1) || first == last)
    {
      node_hash(proof->nodes[i], old_hash, old_hash);
      node_hash(proof->nodes[i], new_hash, new_hash);
      ascend_unpaired(&first, &last);
    }
    else
    {
      node_hash(new_hash, proof->nodes[i], new_hash);
    }
    first >>= 1;
    last >>= 1;
  }
  return last == 0 && memcmp(old_hash, old_root, H) == 0
         && memcmp(new_hash, new_root, H) == 0;
}
