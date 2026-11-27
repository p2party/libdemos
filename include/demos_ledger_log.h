#ifndef DEMOS_LEDGER_LOG_H
#define DEMOS_LEDGER_LOG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/* RFC 9162 tree shape over 64-byte native move IDs, using SHA-512.
   The caller binds the root and tree size to an authenticated checkpoint.
   All functions return 1 on success, 0 on failure. */
#define DEMOS_LOG_HASH_BYTES 64
#define DEMOS_LOG_MAX_PROOF_NODES 65

  typedef struct
  {
    size_t count;
    uint8_t nodes[DEMOS_LOG_MAX_PROOF_NODES][DEMOS_LOG_HASH_BYTES];
  } demos_log_proof;

  /* ids is a contiguous array of count fixed-width move IDs in ledger order.
     NULL is valid for an empty log. Output must be disjoint from the inputs. */
  int demos_log_root(const uint8_t *ids, size_t count,
                     uint8_t root[DEMOS_LOG_HASH_BYTES]);
  int demos_log_inclusion_proof(const uint8_t *ids, size_t count,
                                uint64_t index, demos_log_proof *proof);
  int demos_log_consistency_proof(const uint8_t *ids, size_t count,
                                  uint64_t old_size, demos_log_proof *proof);

  /* Verification requires only trusted root(s), the associated size(s) and the
     untrusted proof. Indices are zero-based. Extra and missing nodes fail. */
  int demos_log_verify_inclusion(uint64_t size, uint64_t index,
                                 const uint8_t id[DEMOS_LOG_HASH_BYTES],
                                 const uint8_t root[DEMOS_LOG_HASH_BYTES],
                                 const demos_log_proof *proof);
  int demos_log_verify_consistency(uint64_t old_size, uint64_t new_size,
                                   const uint8_t old_root[DEMOS_LOG_HASH_BYTES],
                                   const uint8_t new_root[DEMOS_LOG_HASH_BYTES],
                                   const demos_log_proof *proof);

#ifdef __cplusplus
}
#endif
#endif
