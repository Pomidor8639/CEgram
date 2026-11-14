#ifndef CEGRAM_MTPROTO_H
#define CEGRAM_MTPROTO_H

#include "common.h"
#include "transport.h"
#include "crypto.h"

#define TG_CONSTRUCTOR_REQ_PQ_MULTI        0xbe7e8ef1
#define TG_CONSTRUCTOR_RESPQ               0x05162463
#define TG_CONSTRUCTOR_VECTOR              0x1cb5c415
#define TG_CONSTRUCTOR_REQ_DH_PARAMS       0xd712e4be
#define TG_CONSTRUCTOR_P_Q_INNER_DATA_DC   0xa9f55f95
#define TG_CONSTRUCTOR_SERVER_DH_PARAMS_OK 0xd0e8075c

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    uint8_t pq[16];
    size_t pq_len;
    uint64_t fingerprints[8];
    size_t fingerprint_count;
} cegram_respq_t;

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    uint8_t encrypted_answer[1024];
    size_t encrypted_answer_len;
} cegram_server_dh_params_ok_t;

int cegram_mtproto_send_req_pq_multi(cegram_transport_t *t, const uint8_t nonce[16], cegram_respq_t *out_respq);

int cegram_mtproto_send_req_dh_params(cegram_transport_t *t,
                                      const uint8_t nonce[16],
                                      const uint8_t server_nonce[16],
                                      const uint8_t new_nonce[32],
                                      uint32_t p, uint32_t q,
                                      const uint8_t *pq_raw, size_t pq_len,
                                      const cegram_rsa_key_t *key,
                                      int dc_id,
                                      cegram_server_dh_params_ok_t *out_dh);

#endif
