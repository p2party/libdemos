#include "demos_ledger_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIDTH DEMOS_LOG_HASH_BYTES
#define MAX_IDS (1u << 20)

static int
digit(int c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static int
hash_bytes(const char *s, size_t length, uint8_t out[WIDTH])
{
  if (length != 2 + 2 * WIDTH || s[0] != '0' || s[1] != 'x') return 0;
  for (size_t i = 0; i < WIDTH; ++i)
  {
    int hi = digit(s[2 + i * 2]), lo = digit(s[3 + i * 2]);
    if (hi < 0 || lo < 0) return 0;
    out[i] = (uint8_t)(hi * 16 + lo);
  }
  return 1;
}

static int
quantity(const char *s, uint64_t *out)
{
  size_t length = strlen(s);
  if (length < 3 || length > 18 || s[0] != '0' || s[1] != 'x'
      || (s[2] == '0' && length > 3))
    return 0;
  uint64_t value = 0;
  for (size_t i = 2; i < length; ++i)
  {
    int d = digit(s[i]);
    if (d < 0) return 0;
    value = (value << 4) | (unsigned)d;
  }
  *out = value;
  return 1;
}

/* 1 for a record, 0 for EOF on a record boundary, -1 for a malformed stream. */
static int
read_hash(uint8_t out[WIDTH])
{
  char record[2 + 2 * WIDTH + 1];
  size_t n = fread(record, 1, sizeof record, stdin);
  if (n == 0 && !ferror(stdin)) return 0;
  if (n != sizeof record || record[n - 1] != '\n') return -1;
  return hash_bytes(record, n - 1, out) ? 1 : -1;
}

static int
write_hash(const uint8_t h[WIDTH])
{
  static const char hex[] = "0123456789abcdef";
  char record[2 + 2 * WIDTH + 1] = { '0', 'x' };
  for (size_t i = 0; i < WIDTH; ++i)
  {
    record[2 + 2 * i] = hex[h[i] >> 4];
    record[3 + 2 * i] = hex[h[i] & 15];
  }
  record[sizeof record - 1] = '\n';
  return fwrite(record, 1, sizeof record, stdout) == sizeof record;
}

static int
generate(const char *operation, uint64_t pos)
{
  uint8_t *ids = NULL;
  size_t count = 0, capacity = 0;
  uint8_t value[WIDTH];
  int result;
  while ((result = read_hash(value)) == 1)
  {
    if (count == MAX_IDS)
    {
      free(ids);
      return 1;
    }
    if (count == capacity)
    {
      size_t next = capacity ? capacity * 2 : 32;
      uint8_t *larger = realloc(ids, next * WIDTH);
      if (!larger)
      {
        free(ids);
        return 2;
      }
      ids = larger;
      capacity = next;
    }
    memcpy(ids + count++ * WIDTH, value, WIDTH);
  }
  if (result < 0)
  {
    free(ids);
    return ferror(stdin) ? 2 : 1;
  }

  int valid;
  if (strcmp(operation, "root") == 0)
  {
    valid = demos_log_root(ids, count, value) && write_hash(value);
  }
  else
  {
    demos_log_proof proof;
    if (strcmp(operation, "inclusion") == 0)
      valid = demos_log_inclusion_proof(ids, count, pos, &proof);
    else
      valid = demos_log_consistency_proof(ids, count, pos, &proof);
    for (size_t i = 0; valid && i < proof.count; ++i)
      valid = write_hash(proof.nodes[i]);
  }
  free(ids);
  if (fflush(stdout) != 0 || ferror(stdout)) return 2;
  return valid ? 0 : 1;
}

static int
verify(const char *operation, char **args)
{
  uint64_t a, b;
  uint8_t h1[WIDTH], h2[WIDTH];
  if (!quantity(args[0], &a) || !quantity(args[1], &b)
      || !hash_bytes(args[2], strlen(args[2]), h1)
      || !hash_bytes(args[3], strlen(args[3]), h2))
    return 1;

  demos_log_proof proof;
  proof.count = 0;
  int result;
  uint8_t node[WIDTH];
  while ((result = read_hash(node)) == 1)
  {
    if (proof.count == DEMOS_LOG_MAX_PROOF_NODES) return 1;
    memcpy(proof.nodes[proof.count++], node, WIDTH);
  }
  if (result < 0) return ferror(stdin) ? 2 : 1;
  int valid = strcmp(operation, "verify-inclusion") == 0
                  ? demos_log_verify_inclusion(a, b, h1, h2, &proof)
                  : demos_log_verify_consistency(a, b, h1, h2, &proof);
  if (!valid) return 1;
  return puts("ok") == EOF || fflush(stdout) != 0 ? 2 : 0;
}

int
main(int argc, char **argv)
{
  if (argc == 2 && strcmp(argv[1], "root") == 0) return generate(argv[1], 0);
  if (argc == 3
      && (strcmp(argv[1], "inclusion") == 0
          || strcmp(argv[1], "consistency") == 0))
  {
    uint64_t pos;
    return quantity(argv[2], &pos) ? generate(argv[1], pos) : 1;
  }
  if (argc == 6
      && (strcmp(argv[1], "verify-inclusion") == 0
          || strcmp(argv[1], "verify-consistency") == 0))
    return verify(argv[1], argv + 2);
  fputs(
      "usage: demos-ledger-log root | inclusion INDEX | consistency OLD_SIZE\n"
      "       demos-ledger-log verify-inclusion SIZE INDEX MOVE_ID "
      "TRUSTED_ROOT\n"
      "       demos-ledger-log verify-consistency OLD_SIZE NEW_SIZE "
      "TRUSTED_OLD_ROOT TRUSTED_NEW_ROOT\n",
      stderr);
  return 2;
}
