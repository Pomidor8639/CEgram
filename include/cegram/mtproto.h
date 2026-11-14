#ifndef CEGRAM_MTPROTO_H
#define CEGRAM_MTPROTO_H

#include "common.h"
#include "transport.h"
#include "crypto.h"

#define TG_CONSTRUCTOR_REQ_PQ_MULTI         0xbe7e8ef1
#define TG_CONSTRUCTOR_RESPQ                0x05162463
#define TG_CONSTRUCTOR_VECTOR               0x1cb5c415
#define TG_CONSTRUCTOR_REQ_DH_PARAMS        0xd712e4be
#define TG_CONSTRUCTOR_P_Q_INNER_DATA_DC    0xa9f55f95
#define TG_CONSTRUCTOR_SERVER_DH_PARAMS_OK  0xd0e8075c
#define TG_CONSTRUCTOR_SERVER_DH_INNER_DATA 0xb5890dba
#define TG_CONSTRUCTOR_CLIENT_DH_INNER_DATA 0x6643b654
#define TG_CONSTRUCTOR_SET_CLIENT_DH_PARAMS 0xf5045f1f
#define TG_CONSTRUCTOR_DH_GEN_OK            0x3bcbf734
#define TG_CONSTRUCTOR_DH_GEN_RETRY         0x46dc1fb9
#define TG_CONSTRUCTOR_DH_GEN_FAIL          0xa69dae02

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

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    int32_t g;
    uint8_t dh_prime[512];
    size_t dh_prime_len;
    uint8_t g_a[512];
    size_t g_a_len;
    int32_t server_time;
} cegram_server_dh_inner_data_t;

typedef struct {
    uint8_t auth_key[256];
    uint64_t auth_key_id;
    int32_t time_offset;
} cegram_session_t;

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

int cegram_mtproto_decrypt_server_dh_inner(const cegram_server_dh_params_ok_t *server_dh,
                                           const uint8_t new_nonce[32],
                                           cegram_server_dh_inner_data_t *out_inner);

int cegram_mtproto_complete_dh(cegram_transport_t *t,
                              const uint8_t nonce[16],
                              const uint8_t server_nonce[16],
                              const uint8_t new_nonce[32],
                              const cegram_server_dh_inner_data_t *server_dh_inner,
                              cegram_session_t *out_session);

#endif
