#include "demos_ledger_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(e)                                                               \
  do                                                                           \
  {                                                                            \
    if (!(e))                                                                  \
    {                                                                          \
      fprintf(stderr, "line %d: %s\n", __LINE__, #e);                          \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)
#define WIDTH DEMOS_LOG_HASH_BYTES
#define RECORDS 35

int
main(void)
{
  uint8_t ids[RECORDS * WIDTH] = { 0 };
  uint8_t roots[RECORDS + 1][WIDTH];
  demos_log_proof proof;
  for (size_t i = 0; i < RECORDS; ++i)
    ids[i * WIDTH + WIDTH - 1] = (uint8_t)i;
  CHECK(demos_log_root(NULL, 0, roots[0]));
  CHECK(!demos_log_root(NULL, 1, roots[1]));
  CHECK(!demos_log_root(ids, SIZE_MAX, roots[1]));
  CHECK(!demos_log_root(ids, 1, NULL));
  CHECK(!demos_log_inclusion_proof(NULL, 0, 0, &proof));
  CHECK(!demos_log_inclusion_proof(ids, SIZE_MAX, 0, &proof));
  CHECK(!demos_log_consistency_proof(ids, SIZE_MAX, 1, &proof));
  CHECK(!demos_log_inclusion_proof(ids, RECORDS, UINT64_MAX, &proof));
  CHECK(!demos_log_consistency_proof(ids, RECORDS, UINT64_MAX, &proof));
  CHECK(!demos_log_inclusion_proof(ids, 1, 0, NULL));
  CHECK(!demos_log_consistency_proof(ids, 1, 0, NULL));
  CHECK(demos_log_consistency_proof(NULL, 0, 0, &proof) && proof.count == 0);
  CHECK(demos_log_verify_consistency(0, 0, roots[0], roots[0], &proof));
  CHECK(!demos_log_verify_consistency(0, 0, roots[0], ids, &proof));
  CHECK(!demos_log_verify_consistency(1, 0, roots[0], roots[0], &proof));
  CHECK(!demos_log_verify_consistency(0, 0, NULL, roots[0], &proof));
  CHECK(!demos_log_verify_consistency(0, 0, roots[0], NULL, &proof));
  CHECK(!demos_log_verify_consistency(0, 0, roots[0], roots[0], NULL));
  CHECK(!demos_log_verify_inclusion(0, 0, ids, roots[0], &proof));
  CHECK(!demos_log_verify_inclusion(1, 0, NULL, roots[0], &proof));
  CHECK(!demos_log_verify_inclusion(1, 0, ids, NULL, &proof));
  CHECK(!demos_log_verify_inclusion(1, 0, ids, roots[0], NULL));

  for (size_t n = 1; n <= RECORDS; ++n)
  {
    CHECK(demos_log_root(ids, n, roots[n]));
    for (size_t index = 0; index < n; ++index)
    {
      uint8_t *id = ids + WIDTH * index;
      CHECK(demos_log_inclusion_proof(ids, n, index, &proof));
      CHECK(demos_log_verify_inclusion(n, index, id, roots[n], &proof));
      CHECK(!demos_log_verify_inclusion(n, index, id, roots[n - 1], &proof));
      CHECK(!demos_log_verify_inclusion(n, n, id, roots[n], &proof));
      id[0] ^= 1;
      CHECK(!demos_log_verify_inclusion(n, index, id, roots[n], &proof));
      id[0] ^= 1;
      for (size_t j = 0; j < proof.count; ++j)
      {
        proof.nodes[j][0] ^= 1;
        CHECK(!demos_log_verify_inclusion(n, index, id, roots[n], &proof));
        proof.nodes[j][0] ^= 1;
      }
      if (proof.count > 0)
      {
        --proof.count;
        CHECK(!demos_log_verify_inclusion(n, index, id, roots[n], &proof));
        ++proof.count;
      }
      memset(proof.nodes[proof.count++], 0, WIDTH);
      CHECK(!demos_log_verify_inclusion(n, index, id, roots[n], &proof));
    }
    for (size_t old = 0; old <= n; ++old)
    {
      CHECK(demos_log_consistency_proof(ids, n, old, &proof));
      CHECK(demos_log_verify_consistency(old, n, roots[old], roots[n], &proof));
      uint8_t different[WIDTH];
      memcpy(different, roots[old], WIDTH);
      different[0] ^= 1;
      CHECK(!demos_log_verify_consistency(old, n, different, roots[n], &proof));
      if (old > 0)
        CHECK(!demos_log_verify_consistency(old, n, roots[old], roots[n - 1],
                                            &proof));
      for (size_t j = 0; j < proof.count; ++j)
      {
        proof.nodes[j][0] ^= 1;
        CHECK(!demos_log_verify_consistency(old, n, roots[old], roots[n],
                                            &proof));
        proof.nodes[j][0] ^= 1;
      }
      if (proof.count > 0)
      {
        --proof.count;
        CHECK(!demos_log_verify_consistency(old, n, roots[old], roots[n],
                                            &proof));
        ++proof.count;
      }
      memset(proof.nodes[proof.count++], 0, WIDTH);
      CHECK(
          !demos_log_verify_consistency(old, n, roots[old], roots[n], &proof));
    }
  }
  proof.count = SIZE_MAX;
  CHECK(!demos_log_verify_inclusion(UINT64_MAX, 0, ids, roots[0], &proof));
  CHECK(
      !demos_log_verify_consistency(1, UINT64_MAX, roots[1], roots[1], &proof));
  puts("Checked every inclusion and prefix for sizes 1 through 35, changed "
       "nodes and API boundaries.");
  return 0;
}
