#ifndef CEGRAM_CRYPTO_H
#define CEGRAM_CRYPTO_H

#include "common.h"
#include "rsa_keys.h"
#include "aes.h"

int cegram_random_bytes(uint8_t *buf, size_t len);
uint64_t cegram_generate_message_id(void);
void cegram_sha1(const uint8_t *data, size_t len, uint8_t out[20]);
void cegram_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
int cegram_factorize_pq(uint64_t pq, uint32_t *out_p, uint32_t *out_q);
int cegram_rsa_encrypt_pad(const uint8_t *inner_data, size_t inner_len,
                           const cegram_rsa_key_t *key, uint8_t out_encrypted[256]);

void cegram_derive_tmp_aes_keys(const uint8_t new_nonce[32],
                                const uint8_t server_nonce[16],
                                uint8_t out_key[32],
                                uint8_t out_iv[32]);

void cegram_derive_msg_keys(const uint8_t auth_key[256],
                            const uint8_t msg_key[16],
                            int is_client,
                            uint8_t out_key[32],
                            uint8_t out_iv[32]);

#endif
