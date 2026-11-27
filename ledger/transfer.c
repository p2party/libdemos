#include "demos_ledger.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "tagged.h"
#include <string.h>

typedef struct {
  const char *name;
  size_t key_bytes;
  size_t sig_bytes;
  unsigned policy_bit;
} suite_info;

static const suite_info *
suite_for(uint8_t suite)
{
  static const suite_info ml65 = {"ML-DSA-65", 1952, 3309, DEMOS_LEDGER_ALLOW_ML_DSA_65};
  static const suite_info slh192 = {"SLH-DSA-SHA2-192s", 48, 16224, DEMOS_LEDGER_ALLOW_SLH_DSA_SHA2_192S};
  static const suite_info ml87 = {"ML-DSA-87", 2592, 4627, DEMOS_LEDGER_ALLOW_ML_DSA_87};
  static const suite_info slh256 = {"SLH-DSA-SHAKE-256s", 64, 29792, DEMOS_LEDGER_ALLOW_SLH_DSA_SHAKE_256S};
  switch (suite) {
    case DEMOS_LEDGER_ML_DSA_65: return &ml65;
    case DEMOS_LEDGER_SLH_DSA_SHA2_192S: return &slh192;
    case DEMOS_LEDGER_ML_DSA_87: return &ml87;
    case DEMOS_LEDGER_SLH_DSA_SHAKE_256S: return &slh256;
    default: return NULL;
  }
}

/* Fields have fixed widths. An algorithm id determines both variable lengths. */
enum field {
  VERSION = 0, KIND = 1, LEDGER = 2, INPUT_ID = LEDGER + 32,
  WEIGHT = INPUT_ID + 64, EXPIRY = WEIGHT + 8, SPEND_SUITE = EXPIRY + 8,
  RECEIVE_SUITE, DESTINATION, NONCE_HASH = DESTINATION + 64,
  PUBLIC_KEY = NONCE_HASH + 64
};

size_t
demos_ledger_transfer_size(uint8_t suite)
{
  const suite_info *s = suite_for(suite);
  return s ? PUBLIC_KEY + s->key_bytes + s->sig_bytes : 0;
}

static void
put_u64(uint8_t *out, uint64_t n)
{
  for (int i = 7; i >= 0; --i) {
    out[i] = (uint8_t)n;
    n >>= 8;
  }
}

static uint64_t
get_u64(const uint8_t *p)
{
  uint64_t n = 0;
  for (int i = 0; i < 8; ++i) n = (n << 8) | p[i];
  return n;
}

static int
export_public(const suite_info *s, EVP_PKEY *key, uint8_t *out)
{
  size_t n = 0;
  return key && EVP_PKEY_is_a(key, s->name) &&
         EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, out, s->key_bytes, &n) == 1 &&
         n == s->key_bytes;
}

static void
owner_commitment(uint8_t suite, const uint8_t nonce_hash[64], const uint8_t *pub,
                 size_t pub_len, uint8_t out[64])
{
  uint8_t opening[129];
  opening[0] = suite;
  memcpy(opening + 1, nonce_hash, 64);
  crypto_hash_sha512(opening + 65, pub, pub_len);
  tagged_hash("unit/owner", opening, sizeof(opening), out);
}

int
demos_ledger_make_owner(uint8_t suite, EVP_PKEY *key, const uint8_t nonce[32],
                        demos_ledger_owner *out)
{
  const suite_info *s = suite_for(suite);
  uint8_t pub[2592], nonce_hash[64]; /* ML-DSA-87 has the largest public key. */
  if (!s || !nonce || !out || s->key_bytes > sizeof(pub) || !export_public(s, key, pub)) return 0;
  crypto_hash_sha512(nonce_hash, nonce, 32);
  owner_commitment(suite, nonce_hash, pub, s->key_bytes, out->commitment);
  out->suite = suite;
  return 1;
}

static int
accepts_suites(const demos_ledger_policy *policy, const suite_info *spend,
               uint8_t receive_suite)
{
  const suite_info *receive = suite_for(receive_suite);
  return spend && receive && (policy->spend_suites & spend->policy_bit) &&
         (policy->receive_suites & receive->policy_bit);
}

static int
is_denomination(uint64_t weight)
{
  return weight != 0 && (weight & (weight - 1)) == 0;
}

int
demos_ledger_sign_transfer(const demos_ledger_policy *policy, const demos_ledger_unit *current,
                           const demos_ledger_owner *recipient, uint64_t expiry, EVP_PKEY *signer,
                           const uint8_t nonce[32], uint8_t *wire, size_t capacity)
{
  if (!policy || !current || !recipient || !nonce || !wire) return 0;
  const uint8_t suite = current->owner.suite;
  const suite_info *s = suite_for(suite);
  if (!accepts_suites(policy, s, recipient->suite) || !is_denomination(current->weight) ||
      capacity < demos_ledger_transfer_size(suite) || !export_public(s, signer, wire + PUBLIC_KEY)) return 0;

  uint8_t commitment[64], digest[64];
  crypto_hash_sha512(wire + NONCE_HASH, nonce, 32);
  owner_commitment(suite, wire + NONCE_HASH, wire + PUBLIC_KEY, s->key_bytes, commitment);
  if (memcmp(commitment, current->owner.commitment, 64) != 0 ||
      memcmp(commitment, recipient->commitment, 64) == 0) return 0;

  wire[VERSION] = 1;
  wire[KIND] = 1; /* TRANSFER */
  memcpy(wire + LEDGER, policy->ledger_id, 32);
  memcpy(wire + INPUT_ID, current->id, 64);
  put_u64(wire + WEIGHT, current->weight);
  put_u64(wire + EXPIRY, expiry);
  wire[SPEND_SUITE] = suite;
  wire[RECEIVE_SUITE] = recipient->suite;
  memcpy(wire + DESTINATION, recipient->commitment, 64);
  const size_t body_len = PUBLIC_KEY + s->key_bytes;
  tagged_hash("move/body", wire, body_len, digest);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  size_t sig_len = s->sig_bytes;
  int ok = ctx && EVP_DigestSignInit(ctx, NULL, NULL, NULL, signer) == 1 &&
           EVP_DigestSign(ctx, wire + body_len, &sig_len, digest, sizeof(digest)) == 1 &&
           sig_len == s->sig_bytes;
  EVP_MD_CTX_free(ctx);
  return ok;
}

static int
verify_signature(const suite_info *s, const uint8_t *wire)
{
  const size_t body_len = PUBLIC_KEY + s->key_bytes;
  uint8_t digest[64];
  tagged_hash("move/body", wire, body_len, digest);
  EVP_PKEY *key = EVP_PKEY_new_raw_public_key_ex(NULL, s->name, NULL, wire + PUBLIC_KEY, s->key_bytes);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  int ok = key && ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1 &&
           EVP_DigestVerify(ctx, wire + body_len, s->sig_bytes, digest, sizeof(digest)) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return ok;
}

int
demos_ledger_apply_transfer_id(const demos_ledger_policy *policy, uint64_t height,
                               demos_ledger_unit *current, const uint8_t *wire, size_t length,
                               uint8_t move_id[64])
{
  if (!policy || !current || !wire || length < PUBLIC_KEY) return 0;
  const uint8_t suite = current->owner.suite;
  const suite_info *s = suite_for(suite);
  if (wire[VERSION] != 1 || wire[KIND] != 1 || wire[SPEND_SUITE] != suite ||
      !accepts_suites(policy, s, wire[RECEIVE_SUITE]) || length != demos_ledger_transfer_size(suite) ||
      memcmp(wire + LEDGER, policy->ledger_id, 32) != 0 || memcmp(wire + INPUT_ID, current->id, 64) != 0 ||
      !is_denomination(current->weight) || get_u64(wire + WEIGHT) != current->weight) return 0;
  uint64_t expiry = get_u64(wire + EXPIRY);
  if (expiry && height > expiry) return 0;

  uint8_t commitment[64];
  owner_commitment(suite, wire + NONCE_HASH, wire + PUBLIC_KEY, s->key_bytes, commitment);
  if (memcmp(commitment, current->owner.commitment, 64) != 0 ||
      memcmp(commitment, wire + DESTINATION, 64) == 0 || !verify_signature(s, wire)) return 0;

  /* A transfer has exactly one output, at index zero (uint32 big endian). */
  uint8_t move_and_index[68] = {0};
  tagged_hash("move/id", wire, length, move_and_index);
  tagged_hash("unit/id", move_and_index, sizeof(move_and_index), current->id);
  if (move_id) memcpy(move_id, move_and_index, 64);
  current->owner.suite = wire[RECEIVE_SUITE];
  memcpy(current->owner.commitment, wire + DESTINATION, 64);
  return 1;
}

int
demos_ledger_apply_transfer(const demos_ledger_policy *policy, uint64_t height,
                            demos_ledger_unit *current, const uint8_t *wire, size_t length)
{
  return demos_ledger_apply_transfer_id(policy, height, current, wire, length, NULL);
}
