#include "demos_ledger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t
read_u64(const uint8_t *p)
{
  uint64_t n = 0;
  for (size_t i = 0; i < 8; ++i)
    n = (n << 8) | p[i];
  return n;
}

/* Fixed request prefix (183 bytes), followed by exactly one native signed
   transfer. The protocol avoids argv secrets and native struct padding. */
int
main(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "--version") == 0)
  {
    puts("demos-ledger-verify/1");
    return 0;
  }
  if (argc != 1) return 2;
  uint8_t prefix[183], reply[193];
  if (fread(prefix, 1, sizeof prefix, stdin) != sizeof prefix
      || memcmp(prefix, "DLV1", 4) != 0)
    return 1;
  demos_ledger_policy policy
      = { .spend_suites = prefix[36], .receive_suites = prefix[37] };
  if (!policy.spend_suites || (policy.spend_suites & ~DEMOS_LEDGER_KNOWN_SUITE_MASK)
      || !policy.receive_suites || (policy.receive_suites & ~DEMOS_LEDGER_KNOWN_SUITE_MASK))
    return 1;
  memcpy(policy.ledger_id, prefix + 4, 32);
  demos_ledger_unit unit
      = { .weight = read_u64(prefix + 110), .owner.suite = prefix[118] };
  memcpy(unit.id, prefix + 46, 64);
  memcpy(unit.owner.commitment, prefix + 119, 64);
  /* The suite table fixes the allocation before any transfer bytes are read. */
  size_t length = demos_ledger_transfer_size(unit.owner.suite);
  if (!length) return 1;
  uint8_t *wire = malloc(length);
  if (!wire) return 2;
  int ok = fread(wire, 1, length, stdin) == length && fgetc(stdin) == EOF
           && !ferror(stdin) && demos_ledger_apply_transfer_id(
               &policy, read_u64(prefix + 38), &unit, wire, length, reply);
  free(wire);
  if (ferror(stdin)) return 2;
  if (!ok)
    return 1;
  memcpy(reply + 64, unit.id, 64);
  reply[128] = unit.owner.suite;
  memcpy(reply + 129, unit.owner.commitment, 64);
  return fwrite(reply, 1, sizeof reply, stdout) == sizeof reply
                 && fflush(stdout) == 0
             ? 0
             : 2;
}
