#ifndef CEGRAM_CRYPTO_H
#define CEGRAM_CRYPTO_H

#include "common.h"

/* Generate cryptographically secure random bytes */
int cegram_random_bytes(uint8_t *buf, size_t len);

/* Generate MTProto unencrypted message_id based on current time */
uint64_t cegram_generate_message_id(void);

#endif /* CEGRAM_CRYPTO_H */
