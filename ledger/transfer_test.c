#include "demos_ledger.h"

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(e) do { if (!(e)) { fprintf(stderr, "line %d: %s\n", __LINE__, #e); exit(1); } } while (0)

static void
reject(const demos_ledger_policy *policy, uint64_t height, const demos_ledger_unit *in,
       const uint8_t *wire, size_t length)
{
  demos_ledger_unit state = *in;
  CHECK(!demos_ledger_apply_transfer(policy, height, &state, wire, length));
  CHECK(memcmp(state.id, in->id, sizeof(state.id)) == 0 && state.weight == in->weight);
  CHECK(state.owner.suite == in->owner.suite && memcmp(state.owner.commitment, in->owner.commitment, 64) == 0);
}

static void
test_extended_suites(demos_ledger_policy original, demos_ledger_unit state,
                     EVP_PKEY *legacy_key, const uint8_t legacy_nonce[32])
{
  const uint8_t suites[] = {DEMOS_LEDGER_ML_DSA_65, DEMOS_LEDGER_ML_DSA_87,
                            DEMOS_LEDGER_SLH_DSA_SHAKE_256S, DEMOS_LEDGER_ML_DSA_65};
  const unsigned bits[] = {DEMOS_LEDGER_ALLOW_ML_DSA_65, DEMOS_LEDGER_ALLOW_ML_DSA_87,
                           DEMOS_LEDGER_ALLOW_SLH_DSA_SHAKE_256S, DEMOS_LEDGER_ALLOW_ML_DSA_65};
  const size_t sizes[] = {5505, 7463, 30100};
  EVP_PKEY *keys[] = {legacy_key, EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-87"),
                      EVP_PKEY_Q_keygen(NULL, NULL, "SLH-DSA-SHAKE-256s"), legacy_key};
  CHECK(keys[1] && keys[2]);
  uint8_t nonces[4][32] = {{0}, {4}, {5}, {6}};
  memcpy(nonces[0], legacy_nonce, 32);
  demos_ledger_owner destination;
  CHECK(!demos_ledger_make_owner(suites[1], keys[0], nonces[1], &destination));
  CHECK(!demos_ledger_make_owner(suites[2], keys[1], nonces[2], &destination));
  for (size_t i = 0; i < 3; ++i) {
    const size_t n = demos_ledger_transfer_size(suites[i]);
    CHECK(n == sizes[i]);
    uint8_t *wire = malloc(n + 1);
    CHECK(wire);
    CHECK(demos_ledger_make_owner(suites[i + 1], keys[i + 1], nonces[i + 1], &destination));
    /* The network allows just this input suite to spend into this output suite. */
    demos_ledger_policy policy = original;
    policy.spend_suites = bits[i];
    policy.receive_suites = bits[i + 1];
    CHECK(!demos_ledger_sign_transfer(&original, &state, &destination, 0, keys[i], nonces[i], wire, n));
    CHECK(!demos_ledger_sign_transfer(&policy, &state, &destination, 0, keys[i], nonces[i], wire, n - 1));
    CHECK(demos_ledger_sign_transfer(&policy, &state, &destination, 0, keys[i], nonces[i], wire, n));
    reject(&original, 1, &state, wire, n);
    demos_ledger_policy wrong = policy;
    wrong.spend_suites = bits[i + 1];
    reject(&wrong, 1, &state, wire, n);
    wrong = policy;
    wrong.receive_suites = bits[i];
    reject(&wrong, 1, &state, wire, n);
    reject(&policy, 1, &state, wire, n - 1);
    wire[n] = 0;
    reject(&policy, 1, &state, wire, n + 1);
    wire[n - 1] ^= 1;
    reject(&policy, 1, &state, wire, n);
    wire[n - 1] ^= 1;
    CHECK(demos_ledger_apply_transfer(&policy, 1, &state, wire, n));
    CHECK(state.weight == 8 && state.owner.suite == suites[i + 1]);
    CHECK(memcmp(state.owner.commitment, destination.commitment, 64) == 0);
    free(wire);
  }
  EVP_PKEY_free(keys[1]);
  EVP_PKEY_free(keys[2]);
}

int
main(void)
{
  EVP_PKEY *ml = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
  EVP_PKEY *slh = EVP_PKEY_Q_keygen(NULL, NULL, "SLH-DSA-SHA2-192s");
  EVP_PKEY *legacy = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
  CHECK(ml && slh && legacy);
  uint8_t n1[32] = {1}, n2[32] = {2}, n3[32] = {3};
  demos_ledger_owner alice, bob, carol;
  CHECK(demos_ledger_make_owner(DEMOS_LEDGER_ML_DSA_65, ml, n1, &alice));
  CHECK(demos_ledger_make_owner(DEMOS_LEDGER_SLH_DSA_SHA2_192S, slh, n2, &bob));
  CHECK(demos_ledger_make_owner(DEMOS_LEDGER_ML_DSA_65, ml, n3, &carol));
  CHECK(memcmp(alice.commitment, carol.commitment, 64) != 0);
  CHECK(!demos_ledger_make_owner(DEMOS_LEDGER_SLH_DSA_SHA2_192S, ml, n1, &carol));
  CHECK(!demos_ledger_make_owner(DEMOS_LEDGER_ML_DSA_65, legacy, n1, &carol));
  CHECK(demos_ledger_transfer_size(91) == 0);

  /* This unit represents an authenticated genesis or UTXO record. */
  demos_ledger_unit initial = {.id={17}, .weight=8, .owner=alice};
  demos_ledger_unit state = initial;
  unsigned both = DEMOS_LEDGER_ALLOW_ML_DSA_65 | DEMOS_LEDGER_ALLOW_SLH_DSA_SHA2_192S;
  demos_ledger_policy policy = {.ledger_id={12}, .spend_suites=both, .receive_suites=both};
  size_t ml_n = demos_ledger_transfer_size(alice.suite);
  size_t slh_n = demos_ledger_transfer_size(bob.suite);
  CHECK(ml_n == 5505 && slh_n == 16516);
  uint8_t *first = malloc(ml_n + 1), *second = malloc(slh_n);
  CHECK(first && second);

  CHECK(!demos_ledger_sign_transfer(&policy, &state, &bob, 99, ml, n1, first, ml_n-1));
  CHECK(!demos_ledger_sign_transfer(&policy, &state, &bob, 99, ml, n2, first, ml_n));
  CHECK(!demos_ledger_sign_transfer(&policy, &state, &bob, 99, slh, n1, first, ml_n));
  CHECK(!demos_ledger_sign_transfer(&policy, &state, &alice, 99, ml, n1, first, ml_n));
  CHECK(demos_ledger_sign_transfer(&policy, &state, &bob, 99, ml, n1, first, ml_n));
  demos_ledger_policy other = policy;
  other.ledger_id[5] ^= 1;
  reject(&other, 75, &initial, first, ml_n);
  other = policy;
  other.spend_suites = DEMOS_LEDGER_ALLOW_SLH_DSA_SHA2_192S;
  reject(&other, 75, &initial, first, ml_n);
  other = policy;
  other.receive_suites = DEMOS_LEDGER_ALLOW_ML_DSA_65;
  reject(&other, 75, &initial, first, ml_n);
  reject(&policy, 100, &initial, first, ml_n);
  reject(&policy, 75, &initial, first, 0);
  reject(&policy, 75, &initial, first, ml_n-1);
  first[ml_n] = 0;
  reject(&policy, 75, &initial, first, ml_n+1);

  /* Version, kind, chain, input, weight, expiry, both suite IDs, recipient,
     nonce opening, public key and signature all affect verification. */
  const size_t fields[] = {0,1,2,34,98,106,114,115,116,180,244,ml_n-1};
  for (size_t i=0; i<sizeof(fields)/sizeof(fields[0]); ++i) {
    first[fields[i]] ^= 1;
    reject(&policy, 75, &initial, first, ml_n);
    first[fields[i]] ^= 1;
  }
  /* Permit the old suite only for spending, and the new one for outputs. */
  other = policy;
  other.spend_suites = DEMOS_LEDGER_ALLOW_ML_DSA_65;
  other.receive_suites = DEMOS_LEDGER_ALLOW_SLH_DSA_SHA2_192S;
  CHECK(demos_ledger_apply_transfer(&other, 99, &state, first, ml_n));
  CHECK(state.weight == 8 && memcmp(state.id, initial.id, 64) != 0);
  CHECK(state.owner.suite == bob.suite && memcmp(state.owner.commitment, bob.commitment, 64) == 0);
  reject(&policy, 99, &state, first, ml_n);
  CHECK(demos_ledger_sign_transfer(&policy, &state, &carol, 0, slh, n2, second, slh_n));
  second[slh_n-1] ^= 1;
  reject(&policy, 420, &state, second, slh_n);
  second[slh_n-1] ^= 1;
  CHECK(demos_ledger_apply_transfer(&policy, UINT64_MAX, &state, second, slh_n));
  CHECK(state.weight == 8 && state.owner.suite == carol.suite && memcmp(state.owner.commitment, carol.commitment, 64) == 0);
  reject(&policy, 420, &state, second, slh_n);

  test_extended_suites(policy, state, ml, n3);
  free(first);
  free(second);
  EVP_PKEY_free(ml);
  EVP_PKEY_free(slh);
  EVP_PKEY_free(legacy);
  puts("ML-DSA and SLH-DSA transfers, suite migration, replay and rejection checks passed.");
  return 0;
}
