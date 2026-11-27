/* Synthetic interoperability fixture, available only in test builds. No private
 * key leaves this process. */
#include "demos_ledger.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

static void
field(const char *name, const uint8_t *p, size_t n, int last)
{
  printf("\"%s\":\"0x", name);
  for (size_t i = 0; i < n; ++i)
    printf("%02x", p[i]);
  printf(last ? "\"}\n" : "\",");
}

int
main(void)
{
  EVP_PKEY *ml = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
  EVP_PKEY *slh = EVP_PKEY_Q_keygen(NULL, NULL, "SLH-DSA-SHA2-192s");
  demos_ledger_policy policy
      = { .ledger_id = { 12 }, .spend_suites = 3, .receive_suites = 3 };
  uint8_t a[32] = { 1 }, b[32] = { 2 }, c[32] = { 3 };
  demos_ledger_unit start = { .id = { 17 }, .weight = 8 };
  demos_ledger_owner second, third;
  size_t ml_len = demos_ledger_transfer_size(1),
         slh_len = demos_ledger_transfer_size(2);
  uint8_t *first = malloc(ml_len), *alternate = malloc(ml_len),
          *next = malloc(slh_len), *reuse = malloc(slh_len);
  if (!ml || !slh || !first || !alternate || !next || !reuse
      || !demos_ledger_make_owner(1, ml, a, &start.owner)
      || !demos_ledger_make_owner(2, slh, b, &second)
      || !demos_ledger_make_owner(1, ml, c, &third))
    return 1;
  demos_ledger_unit unit = start;
  if (!demos_ledger_sign_transfer(&policy, &unit, &second, 1, ml, a, first,
                                  ml_len)
      || !demos_ledger_sign_transfer(&policy, &unit, &third, 1, ml, a,
                                     alternate, ml_len)
      || !demos_ledger_apply_transfer(&policy, 1, &unit, first, ml_len)
      || !demos_ledger_sign_transfer(&policy, &unit, &third, 0, slh, b, next,
                                     slh_len)
      || !demos_ledger_sign_transfer(&policy, &unit, &start.owner, 0, slh, b,
                                     reuse, slh_len))
    return 1;
  demos_ledger_unit ceiling = { .id = { 34 }, .weight = (UINT64_C(1) << 63) };
  uint8_t n4[32] = { 4 }, n5[32] = { 5 }, n6[32] = { 6 };
  demos_ledger_owner to1, to2;
  uint8_t *max1 = malloc(ml_len), *max2 = malloc(ml_len);
  if (!max1 || !max2 || !demos_ledger_make_owner(1, ml, n4, &ceiling.owner)
      || !demos_ledger_make_owner(1, ml, n5, &to1)
      || !demos_ledger_make_owner(1, ml, n6, &to2)
      || !demos_ledger_sign_transfer(&policy, &ceiling, &to1, 0, ml, n4, max1,
                                     ml_len)
      || !demos_ledger_sign_transfer(&policy, &ceiling, &to2, 0, ml, n4, max2,
                                     ml_len))
    return 1;
  putchar('{');
  field("ceilingId", ceiling.id, 64, 0);
  field("ceilingCommitment", ceiling.owner.commitment, 64, 0);
  field("ceilingFirst", max1, ml_len, 0);
  field("ceilingAlternate", max2, ml_len, 0);
  free(max1);
  free(max2);
  field("chainId", policy.ledger_id, 32, 0);
  field("inputId", start.id, 64, 0);
  field("commitment", start.owner.commitment, 64, 0);
  field("first", first, ml_len, 0);
  field("alternate", alternate, ml_len, 0);
  field("second", next, slh_len, 0);
  field("reuse", reuse, slh_len, 1);
  free(first);
  free(next);
  free(alternate);
  free(reuse);
  EVP_PKEY_free(ml);
  EVP_PKEY_free(slh);
  return 0;
}
