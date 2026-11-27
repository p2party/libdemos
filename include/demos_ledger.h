#ifndef DEMOS_LEDGER_H
#define DEMOS_LEDGER_H

#include <openssl/types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Experimental transfer format version 1. All functions return 1 on success. */
enum demos_ledger_suite {
  DEMOS_LEDGER_ML_DSA_65 = 1,
  DEMOS_LEDGER_SLH_DSA_SHA2_192S = 2
};
#define DEMOS_LEDGER_ALLOW_ML_DSA_65 1u
#define DEMOS_LEDGER_ALLOW_SLH_DSA_SHA2_192S 2u

typedef struct {
  uint8_t suite;
  uint8_t commitment[64];
} demos_ledger_owner;

typedef struct {
  uint8_t id[64];
  uint64_t weight;
  demos_ledger_owner owner;
} demos_ledger_unit;

/* The application supplies the agreed policy at the validation height.
   Separate masks allow migration away from a retiring spend algorithm. */
typedef struct {
  uint8_t ledger_id[32];
  unsigned spend_suites;
  unsigned receive_suites;
} demos_ledger_policy;

/* Zero indicates an unsupported suite. */
size_t demos_ledger_transfer_size(uint8_t signing_suite);

/* The recipient supplies a fresh random 32-byte nonce and a matching public
   key. Only the suite and commitment need to go to the previous owner. */
int demos_ledger_make_owner(uint8_t suite, EVP_PKEY *key,
                            const uint8_t nonce[32], demos_ledger_owner *out);

/* Writes one complete authorization to wire on success. expiry=0 has no limit.
   Allocate demos_ledger_transfer_size(current->owner.suite) bytes. */
int demos_ledger_sign_transfer(const demos_ledger_policy *policy,
                               const demos_ledger_unit *current,
                               const demos_ledger_owner *recipient,
                               uint64_t expiry, EVP_PKEY *signer,
                               const uint8_t nonce[32], uint8_t *wire,
                               size_t capacity);

/* current must be the authentic, unspent input. Replaces it only on success.
   A persistent caller must serialize updates and atomically compare-and-swap
   the input id. This function alone does not establish chain order. */
int demos_ledger_apply_transfer(const demos_ledger_policy *policy,
                                uint64_t height, demos_ledger_unit *current,
                                const uint8_t *wire, size_t length);

/* As above, also writes the native move ID on success when move_id is
   non-null. Its 64-byte output must be disjoint from current and wire. */
int demos_ledger_apply_transfer_id(const demos_ledger_policy *policy,
                                  uint64_t height, demos_ledger_unit *current,
                                  const uint8_t *wire, size_t length,
                                  uint8_t move_id[64]);

#ifdef __cplusplus
}
#endif
#endif
