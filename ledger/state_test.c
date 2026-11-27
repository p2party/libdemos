#include "demos_ledger_state.h"
#include <stdio.h>
#include <string.h>

#define CHECK(test)                                                            \
  do                                                                           \
  {                                                                            \
    if (!(test))                                                               \
    {                                                                          \
      fprintf(stderr, "failed at %d: %s\n", __LINE__, #test);                  \
      return 1;                                                                \
    }                                                                          \
  } while (0)

int
main(void)
{
  demos_state *a = demos_state_new(), *b = demos_state_new();
  uint8_t initial[64], old[64], next[64], expected[64], id[64] = { 0 };
  uint8_t proof[DEMOS_STATE_MAX_PROOF];
  size_t size = 0;
  CHECK(a && b && demos_state_root(a, initial));
  CHECK(!demos_state_insert(a, 0, id));
  CHECK(!demos_state_insert(a, DEMOS_STATE_OWNER, NULL));
  CHECK(!demos_state_verify(initial, DEMOS_STATE_OWNER, id, 2, proof, 0));
  for (unsigned i = 0; i < 60; ++i)
  {
    enum demos_state_kind kind = (enum demos_state_kind)(1 + i % 3);
    id[63] = (uint8_t)(i / 3);
    CHECK(demos_state_root(a, old));
    CHECK(!demos_state_prove(a, kind, id, proof, DEMOS_STATE_PROOF_HEADER - 1,
                             &size));
    CHECK(demos_state_prove(a, kind, id, proof, sizeof(proof), &size));
    CHECK(!demos_state_prove(a, kind, id, proof, size - 1, &size));
    CHECK(demos_state_prove(a, kind, id, proof, size, &size));
    CHECK(demos_state_verify(old, kind, id, 0, proof, size));
    CHECK(!demos_state_verify(old, kind, id, 1, proof, size));
    CHECK(!demos_state_insert_root(old, kind, id, proof, size, NULL));
    CHECK(demos_state_insert_root(old, kind, id, proof, size, old));
    CHECK(demos_state_insert(a, kind, id));
    CHECK(!demos_state_insert(a, kind, id));
    CHECK(demos_state_root(a, next) && !memcmp(old, next, 64));
    CHECK(!demos_state_verify(next, kind, id, 0, proof, size));
    CHECK(demos_state_prove(a, kind, id, proof, sizeof(proof), &size));
    CHECK(demos_state_verify(next, kind, id, 1, proof, size));
    memcpy(expected, initial, 64);
    CHECK(!demos_state_insert_root(next, kind, id, proof, size, expected));
    CHECK(!memcmp(expected, initial, 64));
  }
  for (int i = 59; i >= 0; --i)
  {
    id[63] = (uint8_t)(i / 3);
    CHECK(demos_state_insert(b, (enum demos_state_kind)(1 + i % 3), id));
  }
  CHECK(demos_state_root(b, expected) && !memcmp(expected, next, 64));
  demos_state_free(b);
  demos_state_free(a);
  demos_state_free(NULL);
  return 0;
}
