#include "demos_ledger_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Bounded offline snapshot ingestion. The verifier reads only a compact proof.
 */
#define MAX_RECORDS 65536u
static enum demos_state_kind
kind_of(const char *name)
{
  if (!strcmp(name, "spent")) return DEMOS_STATE_SPENT;
  if (!strcmp(name, "move")) return DEMOS_STATE_MOVE;
  if (!strcmp(name, "owner")) return DEMOS_STATE_OWNER;
  return 0;
}

static int
hex_nibble(char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static int
parse_id(const char *s, uint8_t id[64])
{
  if (strlen(s) != 130 || s[0] != '0' || s[1] != 'x') return 0;
  for (unsigned i = 0; i < 64; ++i)
  {
    int hi = hex_nibble(s[2 + i * 2]), lo = hex_nibble(s[3 + i * 2]);
    if (hi < 0 || lo < 0) return 0;
    id[i] = (uint8_t)((hi << 4) | lo);
  }
  return 1;
}

static int
write_root(const uint8_t root[64])
{
  char buf[131] = { '0', 'x' };
  const char digits[] = "0123456789abcdef";
  for (unsigned i = 0; i < 64; ++i)
  {
    buf[2 + 2 * i] = digits[root[i] >> 4];
    buf[3 + 2 * i] = digits[root[i] & 15];
  }
  buf[130] = '\n';
  return fwrite(buf, 1, sizeof(buf), stdout) == sizeof(buf);
}

static FILE *
readable(const char *name)
{
  return !strcmp(name, "-") ? stdin : fopen(name, "rb");
}

static int
read_set(FILE *f, demos_state *tree)
{
  char line[138];
  unsigned count = 0;
  while (fgets(line, sizeof(line), f))
  {
    size_t n = strlen(line);
    if (n == 0 || line[n - 1] != '\n' || count == MAX_RECORDS) return 0;
    ++count;
    line[n - 1] = 0;
    char *space = strchr(line, ' ');
    if (!space) return 0;
    *space = 0;
    uint8_t id[64];
    if (!parse_id(space + 1, id)
        || !demos_state_insert(tree, kind_of(line), id))
      return 0;
  }
  return !ferror(f);
}

static int
generate(const char *filename, enum demos_state_kind kind, const uint8_t *id)
{
  demos_state *tree = demos_state_new();
  if (!tree) return 2;
  FILE *f = readable(filename);
  int rc = 2;
  if (f)
  {
    int valid = read_set(f, tree);
    rc = ferror(f) ? 2 : valid ? 0 : 1;
    if (f != stdin && fclose(f) != 0) rc = 2;
  }
  if (!rc && kind)
  {
    uint8_t proof[DEMOS_STATE_MAX_PROOF];
    size_t size;
    if (!demos_state_prove(tree, kind, id, proof, sizeof(proof), &size)
        || fwrite(proof, 1, size, stdout) != size)
      rc = 2;
  }
  else if (!rc)
  {
    uint8_t root[64];
    if (!demos_state_root(tree, root) || !write_root(root)) rc = 2;
  }
  demos_state_free(tree);
  return rc;
}

static int
check(const char *filename, const uint8_t root[64], enum demos_state_kind kind,
      const uint8_t id[64], int present, int insert)
{
  uint8_t proof[DEMOS_STATE_MAX_PROOF], next[64];
  FILE *f = readable(filename);
  if (!f) return 2;
  size_t size = fread(proof, 1, sizeof(proof), f);
  int trailing = fgetc(f);
  int rc = ferror(f) ? 2 : trailing != EOF ? 1 : 0;
  if (f != stdin && fclose(f) != 0) rc = 2;
  if (rc) return rc;
  if (insert)
  {
    if (!demos_state_insert_root(root, kind, id, proof, size, next)) return 1;
    return write_root(next) ? 0 : 2;
  }
  if (!demos_state_verify(root, kind, id, present, proof, size)) return 1;
  return puts("ok") >= 0 ? 0 : 2;
}

int
main(int argc, char **argv)
{
  uint8_t root[64], id[64];
  enum demos_state_kind kind;
  int rc;
  if (argc == 3 && !strcmp(argv[1], "root"))
  {
    rc = generate(argv[2], 0, NULL);
  }
  else if (argc == 5 && !strcmp(argv[1], "prove"))
  {
    if (!(kind = kind_of(argv[3])) || !parse_id(argv[4], id)) return 1;
    rc = generate(argv[2], kind, id);
  }
  else if ((argc == 7 && !strcmp(argv[1], "verify"))
           || (argc == 6 && !strcmp(argv[1], "insert-root")))
  {
    if (!parse_id(argv[2], root) || !(kind = kind_of(argv[3]))
        || !parse_id(argv[4], id))
      return 1;
    int insert = argc == 6;
    int present = !insert && !strcmp(argv[5], "present");
    if (!insert && !present && strcmp(argv[5], "absent")) return 1;
    rc = check(argv[argc - 1], root, kind, id, present, insert);
  }
  else
  {
    fputs("usage: demos-ledger-state root SET | prove SET KIND ID | "
          "verify ROOT KIND ID present|absent PROOF | insert-root ROOT KIND ID "
          "PROOF\n",
          stderr);
    return 2;
  }
  return fflush(stdout) != 0 ? 2 : rc;
}
