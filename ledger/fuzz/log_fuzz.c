#include "demos_ledger_log.h"

#include <stdlib.h>

#define WIDTH DEMOS_LOG_HASH_BYTES
#define MAX_LEAVES 40

/* Build small synthetic histories, check generated proofs, then corrupt them.
 */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  if (size < 3) return 0;
  size_t count = data[0] % (MAX_LEAVES + 1);
  size_t old = data[1] % (count + 1);
  uint8_t ids[MAX_LEAVES * WIDTH];
  for (size_t i = 0; i < count * WIDTH; ++i)
    ids[i] = data[i % size] ^ (uint8_t)(i / WIDTH);

  uint8_t old_root[WIDTH], root[WIDTH];
  demos_log_proof proof;
  if (!demos_log_root(ids, count, root) || !demos_log_root(ids, old, old_root)
      || !demos_log_consistency_proof(ids, count, old, &proof)
      || !demos_log_verify_consistency(old, count, old_root, root, &proof))
    abort();
  if (proof.count > 0)
  {
    proof.nodes[data[2] % proof.count][data[1] % WIDTH] ^= 1;
    if (demos_log_verify_consistency(old, count, old_root, root, &proof))
      abort();
  }

  if (count > 0)
  {
    size_t index = data[2] % count;
    uint8_t *id = ids + index * WIDTH;
    if (!demos_log_inclusion_proof(ids, count, index, &proof)
        || !demos_log_verify_inclusion(count, index, id, root, &proof))
      abort();
    id[data[1] % WIDTH] ^= 1;
    if (demos_log_verify_inclusion(count, index, id, root, &proof)) abort();
  }
  return 0;
}
