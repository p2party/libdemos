#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/demos.h"

int
main()
{
  int res;

  const unsigned int IDENTITIES_LEN = 14;

  uint8_t *nonces = (uint8_t *)malloc(
      sizeof(uint8_t[IDENTITIES_LEN * crypto_auth_hmacsha512_KEYBYTES]));
  if (nonces == NULL)
  {
    printf("ERROR: Could not allocate space for nonces\n");

    return -1;
  }

  printf("INFO: Allocated space for nonces\n");

  uint8_t *public_keys = (uint8_t *)malloc(
      sizeof(uint8_t[IDENTITIES_LEN * crypto_sign_ed25519_PUBLICKEYBYTES]));
  if (public_keys == NULL)
  {
    printf("ERROR: Could not allocate space for public keys\n");
    free(nonces);

    return -2;
  }

  printf("INFO: Allocated space for public keys\n");

  uint8_t *secret_keys = (uint8_t *)malloc(
      sizeof(uint8_t[IDENTITIES_LEN * crypto_sign_ed25519_SECRETKEYBYTES]));
  if (secret_keys == NULL)
  {
    free(nonces);
    free(public_keys);

    printf("ERROR: Could not allocate space for secret keys\n");

    return -3;
  }

  printf("INFO: Allocated space for secret keys\n");

  res = generate_identities(IDENTITIES_LEN, nonces, public_keys, secret_keys);
  if (res != 0)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);

    printf("ERROR: Could not generate identities\n");

    return -4;
  }

  printf("INFO: Generated identities\n");

  uint8_t *commit_details
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_auth_hmacsha512_BYTES]));
  if (commit_details == NULL)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);

    printf("ERROR: Could not allocate space for commit details\n");

    return -5;
  }

  printf("INFO: Allocated space for commit details\n");

  res = generate_commit_details(IDENTITIES_LEN, nonces, public_keys,
                                commit_details);
  if (res != 0)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);

    printf("ERROR: Could not generate commit details\n");

    return -6;
  }

  printf("INFO: Generated commit details\n");

  uint8_t *current_commit
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (current_commit == NULL)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);

    printf("ERROR: Could allocate space for initial commit\n");

    return -7;
  }

  printf("INFO: Allocated space for current commit\n");

  uint8_t *initial_commit
      = (uint8_t *)malloc(sizeof(uint8_t[crypto_hash_sha512_BYTES]));
  if (initial_commit == NULL)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(commit_details);
    free(current_commit);

    printf("ERROR: Could allocate space for initial commit\n");

    return -8;
  }

  printf("INFO: Allocated space for initial commit\n");

  random_bytes(crypto_hash_sha512_BYTES, initial_commit);

  res = commit(current_commit, initial_commit, commit_details);
  free(commit_details);
  if (res != 0)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    printf("ERROR: Could not reversibly update the initial commit\n");

    return -9;
  }

  const unsigned int IDENTITY_INDEX_USED = IDENTITIES_LEN - 2;

  const unsigned int PROOF_LEN = crypto_hash_sha512_BYTES
                                 + (IDENTITIES_LEN - IDENTITY_INDEX_USED)
                                       * (crypto_sign_ed25519_PUBLICKEYBYTES
                                          + crypto_auth_hmacsha512_KEYBYTES)
                                 + crypto_sign_ed25519_BYTES;
  uint8_t *proof = (uint8_t *)malloc(sizeof(uint8_t[PROOF_LEN]));
  if (proof == NULL)
  {
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    printf("ERROR: Could not allocate commitment proof\n");

    return -10;
  }

  printf("INFO: Allocated proof\n");

  res = generate_proof(
      PROOF_LEN, IDENTITIES_LEN, current_commit, initial_commit, nonces,
      public_keys,
      secret_keys + IDENTITY_INDEX_USED * crypto_sign_ed25519_SECRETKEYBYTES,
      proof);
  if (res != 0)
  {
    free(proof);
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    printf("ERROR: Could not generate ownership proof %d\n", res);

    return -11;
  }

  printf("INFO: Generated ownership proof\n");

  uint8_t *tampered_proof = (uint8_t *)malloc(PROOF_LEN * sizeof(uint8_t));
  if (tampered_proof == NULL)
  {
    free(proof);
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    printf("ERROR: Could not allocate tampered proof\n");

    return -12;
  }

  printf("INFO: Allocated tampered proof\n");

  const unsigned int SIGNATURE_START = PROOF_LEN - crypto_sign_ed25519_BYTES;
  const int EXPECTED_DISTANCE = IDENTITIES_LEN - IDENTITY_INDEX_USED;
  unsigned int failures = 0;

  const int distance = verify_proof(PROOF_LEN, current_commit, proof);
  if (distance == EXPECTED_DISTANCE)
  {
    printf("PASS: verify_proof accepts an honest proof\n");
  }
  else
  {
    printf("FAIL: verify_proof accepts an honest proof (expected %d, got "
           "%d)\n",
           EXPECTED_DISTANCE, distance);
    failures++;
  }

  memcpy(tampered_proof, proof, PROOF_LEN);
  memset(&tampered_proof[SIGNATURE_START], 0, crypto_sign_ed25519_BYTES);
  res = verify_proof(PROOF_LEN, current_commit, tampered_proof);
  if (res == -11)
  {
    printf("PASS: verify_proof rejects a zeroed signature\n");
  }
  else
  {
    printf("FAIL: verify_proof rejects a zeroed signature (expected -11, got "
           "%d)\n",
           res);
    failures++;
  }

  // Flip each of the 512 signature bits in turn; every flip must be rejected.
  unsigned int flips_not_rejected = 0;
  for (size_t i = 0; i < crypto_sign_ed25519_BYTES * 8; i++)
  {
    memcpy(tampered_proof, proof, PROOF_LEN);
    tampered_proof[SIGNATURE_START + i / 8] ^= (uint8_t)(1U << (i % 8));
    res = verify_proof(PROOF_LEN, current_commit, tampered_proof);
    if (res != -11) flips_not_rejected++;
  }
  if (flips_not_rejected == 0)
  {
    printf("PASS: verify_proof rejects a flipped signature bit\n");
  }
  else
  {
    printf("FAIL: verify_proof rejects a flipped signature bit (%u of %u "
           "flips not rejected)\n",
           flips_not_rejected, crypto_sign_ed25519_BYTES * 8);
    failures++;
  }

  // A valid signature over the same commit, made by identity 0 instead of
  // the identity whose public key opens the proof.
  memcpy(tampered_proof, proof, PROOF_LEN);
  res = sign(crypto_hash_sha512_BYTES, current_commit, secret_keys,
             &tampered_proof[SIGNATURE_START]);
  if (res != 0)
  {
    free(tampered_proof);
    free(proof);
    free(nonces);
    free(public_keys);
    free(secret_keys);
    free(initial_commit);
    free(current_commit);

    printf("ERROR: Could not sign with a different key\n");

    return -13;
  }

  res = verify_proof(PROOF_LEN, current_commit, tampered_proof);
  if (res == -11)
  {
    printf("PASS: verify_proof rejects a signature by a different key\n");
  }
  else
  {
    printf("FAIL: verify_proof rejects a signature by a different key "
           "(expected -11, got %d)\n",
           res);
    failures++;
  }

  free(tampered_proof);
  free(proof);
  free(nonces);
  free(public_keys);
  free(secret_keys);
  free(initial_commit);
  free(current_commit);

  if (failures > 0)
  {
    printf("ERROR: %u verify_proof check(s) failed\n", failures);

    return -14;
  }

  printf("SUCCESS. Identity's distance from commit was %i\n", distance);

  return 0;
}
