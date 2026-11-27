#include "demos_ledger_state.h"

#include <stdlib.h>
#include <string.h>

/* A public claim + root followed by a possibly malformed DSS1 wire proof. */
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const size_t prefix = 2 + 2 * DEMOS_STATE_BYTES;
  if (size < prefix || size - prefix > DEMOS_STATE_MAX_PROOF) return 0;
  const uint8_t *root = data + 2, *id = root + DEMOS_STATE_BYTES,
                *proof = data + prefix;
  size_t length = size - prefix;
  enum demos_state_kind kind = (enum demos_state_kind)data[0];
  int present = data[1];
  uint8_t next[64];
  if (demos_state_verify(root, kind, id, present, proof, length)
      && present == 0)
  {
    uint8_t occupied[DEMOS_STATE_MAX_PROOF];
    if (!demos_state_insert_root(root, kind, id, proof, length, next)) abort();
    memcpy(occupied, proof, length);
    occupied[5] = 1;
    if (!demos_state_verify(next, kind, id, 1, occupied, length)) abort();
  }
  return 0;
}
