#include "demos_ledger.h"
#include <stdio.h>
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
  uint8_t prefix[183], wire[16516 + 1], reply[193];
  if (fread(prefix, 1, sizeof prefix, stdin) != sizeof prefix)
    return ferror(stdin) ? 2 : 1;
  if (memcmp(prefix, "DLV1", 4) != 0) return 1;
  size_t n = fread(wire, 1, sizeof wire, stdin);
  if (ferror(stdin)) return 2;
  if (!feof(stdin) || n == sizeof wire) return 1;
  demos_ledger_policy policy
      = { .spend_suites = prefix[36], .receive_suites = prefix[37] };
  if (policy.spend_suites == 0 || policy.spend_suites > 3
      || policy.receive_suites == 0 || policy.receive_suites > 3)
    return 1;
  memcpy(policy.ledger_id, prefix + 4, 32);
  demos_ledger_unit unit
      = { .weight = read_u64(prefix + 110), .owner.suite = prefix[118] };
  memcpy(unit.id, prefix + 46, 64);
  memcpy(unit.owner.commitment, prefix + 119, 64);
  const int status = demos_ledger_apply_transfer_status(
      &policy, read_u64(prefix + 38), &unit, wire, n, reply);
  if (status != 1) return status < 0 ? 2 : 1;
  memcpy(reply + 64, unit.id, 64);
  reply[128] = unit.owner.suite;
  memcpy(reply + 129, unit.owner.commitment, 64);
  return fwrite(reply, 1, sizeof reply, stdout) == sizeof reply
                 && fflush(stdout) == 0
             ? 0
             : 2;
}
