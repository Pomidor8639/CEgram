#ifndef CEGRAM_MTPROTO_H
#define CEGRAM_MTPROTO_H

#include "common.h"
#include "transport.h"
#include "crypto.h"

#define TG_CONSTRUCTOR_REQ_PQ_MULTI 0xbe7e8ef1
#define TG_CONSTRUCTOR_RESPQ        0x05162463
#define TG_CONSTRUCTOR_VECTOR       0x1cb5c415

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    uint8_t pq[16];
    size_t pq_len;
    uint64_t fingerprints[8];
    size_t fingerprint_count;
} cegram_respq_t;

/* Send req_pq_multi and receive resPQ from connected DC */
int cegram_mtproto_send_req_pq_multi(cegram_transport_t *t, const uint8_t nonce[16], cegram_respq_t *out_respq);

#endif /* CEGRAM_MTPROTO_H */
