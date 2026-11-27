#ifndef DEMOS_LEDGER_STATE_H
#define DEMOS_LEDGER_STATE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

  enum demos_state_kind
  {
    DEMOS_STATE_SPENT = 1,
    DEMOS_STATE_MOVE = 2,
    DEMOS_STATE_OWNER = 3
  };

#define DEMOS_STATE_BYTES 64u
#define DEMOS_STATE_PROOF_HEADER (6u + 2u * DEMOS_STATE_BYTES)
#define DEMOS_STATE_MAX_PROOF                                                  \
  (DEMOS_STATE_PROOF_HEADER + 512u * DEMOS_STATE_BYTES)

  typedef struct demos_state demos_state;

  /* A new empty set. Free it after use. Methods on a single tree require
     external synchronization when it is being mutated. */
  demos_state *demos_state_new(void);
  void demos_state_free(demos_state *tree);
  /* Atomic in-memory insertion. A duplicate, invalid argument, or allocation
     failure returns zero, preserving the previous root. */
  int demos_state_insert(demos_state *tree, enum demos_state_kind kind,
                         const uint8_t id[64]);
  int demos_state_root(const demos_state *tree, uint8_t root[64]);

  /* Output is the canonical DSS1 wire format. A full-size buffer always fits.
     On success *size is its exact byte length. Output cannot overlap inputs. */
  int demos_state_prove(const demos_state *tree, enum demos_state_kind kind,
                        const uint8_t id[64], uint8_t *proof, size_t capacity,
                        size_t *size);

  /* Verifiers take their expected root and claim independently of the proof.
     present is 0 or 1. authenticated_root must name the intended checkpoint. */
  int demos_state_verify(const uint8_t authenticated_root[64],
                         enum demos_state_kind kind, const uint8_t id[64],
                         int present, const uint8_t *proof, size_t size);
  /* Verify absence under the previous root and calculate the unique updated
     root. Output is written only on success and may alias the old root. */
  int demos_state_insert_root(const uint8_t authenticated_root[64],
                              enum demos_state_kind kind, const uint8_t id[64],
                              const uint8_t *proof, size_t size,
                              uint8_t next_root[64]);

#ifdef __cplusplus
}
#endif
#endif
