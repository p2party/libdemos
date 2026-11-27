#ifndef DEMOS_LEDGER_TAGGED_H
#define DEMOS_LEDGER_TAGGED_H

#include <sodium/crypto_hash_sha512.h>
#include <stdint.h>
#include <string.h>

/* Every caller uses a fixed, short ASCII domain. */
static inline void
tagged_hash(const char *tag, const uint8_t *data, size_t length,
            uint8_t out[64])
{
  crypto_hash_sha512_state hash;
  uint8_t n = (uint8_t)strlen(tag);
  crypto_hash_sha512_init(&hash);
  crypto_hash_sha512_update(&hash, &n, 1);
  crypto_hash_sha512_update(&hash, (const uint8_t *)tag, n);
  crypto_hash_sha512_update(&hash, data, length);
  crypto_hash_sha512_final(&hash, out);
}

#endif
