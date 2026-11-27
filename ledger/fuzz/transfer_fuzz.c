#include "demos_ledger.h"
#include <stdlib.h>
#include <string.h>

/* Corpus records consist of an input unit ID, a public owner commitment, a
 * signing suite byte and the complete wire message. The test chain has one
 * spendable unit of weight eight per independent case. */
static int
same_unit(const demos_ledger_unit *a, const demos_ledger_unit *b)
{
  return a->weight == b->weight && a->owner.suite == b->owner.suite
         && !memcmp(a->id, b->id, sizeof a->id)
         && !memcmp(a->owner.commitment, b->owner.commitment, sizeof a->owner.commitment);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  const demos_ledger_policy policy = {
    .ledger_id = {12},
    .spend_suites = DEMOS_LEDGER_ALLOW_ML_DSA_65 | DEMOS_LEDGER_ALLOW_SLH_DSA_SHA2_192S,
    .receive_suites = DEMOS_LEDGER_ALLOW_ML_DSA_65 | DEMOS_LEDGER_ALLOW_SLH_DSA_SHA2_192S
  };
  demos_ledger_unit input = {.weight = 8};
  const size_t prefix = sizeof input.id + sizeof input.owner.commitment + 1;
  if (size < prefix) return 0;
  memcpy(input.id, data, sizeof input.id);
  memcpy(input.owner.commitment, data + sizeof input.id, sizeof input.owner.commitment);
  input.owner.suite = data[prefix - 1];

  const uint8_t *wire = data + prefix;
  const size_t length = size - prefix;
  demos_ledger_unit unit = input;
  if (!demos_ledger_apply_transfer(&policy, 1, &unit, wire, length)) {
    if (!same_unit(&input, &unit)) abort();
    return 0;
  }

  if (unit.weight != input.weight || !memcmp(unit.id, input.id, sizeof unit.id)
      || !memcmp(unit.owner.commitment, input.owner.commitment, sizeof unit.owner.commitment))
    abort();
  demos_ledger_unit after = unit;
  if (demos_ledger_apply_transfer(&policy, 1, &after, wire, length) || !same_unit(&after, &unit))
    abort();
  return 0;
}
