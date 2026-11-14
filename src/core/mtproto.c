#include "cegram/mtproto.h"

int cegram_mtproto_send_req_pq_multi(cegram_transport_t *t, const uint8_t nonce[16], cegram_respq_t *out_respq) {
    uint8_t packet[64];
    uint8_t recv_buf[512];
    size_t recv_len = 0;
    uint64_t auth_key_id = 0;
    uint64_t msg_id = cegram_generate_message_id();
    uint32_t msg_data_len = 4 + 16; /* constructor (4) + nonce (16) = 20 */
    uint32_t constructor = TG_CONSTRUCTOR_REQ_PQ_MULTI;
    size_t offset = 0;
    size_t i;

    if (!t || !nonce || !out_respq) {
        return CEGRAM_ERR_GENERIC;
    }

    memset(out_respq, 0, sizeof(*out_respq));

    /* Assemble unencrypted MTProto message:
     * auth_key_id (8 bytes) = 0
     * message_id (8 bytes)
     * message_data_length (4 bytes)
     * message_data:
     *   constructor req_pq_multi (4 bytes)
     *   nonce (16 bytes)
     */
    memcpy(packet + offset, &auth_key_id, 8); offset += 8;
    memcpy(packet + offset, &msg_id, 8); offset += 8;
    memcpy(packet + offset, &msg_data_len, 4); offset += 4;
    memcpy(packet + offset, &constructor, 4); offset += 4;
    memcpy(packet + offset, nonce, 16); offset += 16;

    /* Send packet */
    if (cegram_transport_send(t, packet, offset) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    /* Receive resPQ */
    if (cegram_transport_recv(t, recv_buf, sizeof(recv_buf), &recv_len) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    /* Parse unencrypted response header:
     * [0..7]: auth_key_id (must be 0)
     * [8..15]: message_id
     * [16..19]: message_data_length
     * [20..]: payload
     */
    if (recv_len < 24) {
        return CEGRAM_ERR_SCHEMA;
    }

    offset = 20; /* Skip MTProto header */

    /* Check constructor: resPQ#05162463 */
    uint32_t resp_constructor;
    memcpy(&resp_constructor, recv_buf + offset, 4); offset += 4;
    if (resp_constructor != TG_CONSTRUCTOR_RESPQ) {
        return CEGRAM_ERR_SCHEMA;
    }

    /* Read nonce (16 bytes) */
    memcpy(out_respq->nonce, recv_buf + offset, 16); offset += 16;

    /* Verify nonce matches request */
    if (memcmp(out_respq->nonce, nonce, 16) != 0) {
        return CEGRAM_ERR_SCHEMA;
    }

    /* Read server_nonce (16 bytes) */
    memcpy(out_respq->server_nonce, recv_buf + offset, 16); offset += 16;

    /* Read pq bytes (TL string format: length byte + data + padding to 4 bytes) */
    uint8_t pq_first_byte = recv_buf[offset++];
    size_t pq_data_len = 0;
    if (pq_first_byte <= 253) {
        pq_data_len = pq_first_byte;
    } else {
        /* Not expected for PQ (PQ is 8 bytes) */
        return CEGRAM_ERR_SCHEMA;
    }

    if (pq_data_len > sizeof(out_respq->pq) || (offset + pq_data_len > recv_len)) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_respq->pq, recv_buf + offset, pq_data_len);
    out_respq->pq_len = pq_data_len;
    offset += pq_data_len;

    /* Skip padding so (1 + pq_data_len + padding) % 4 == 0 */
    size_t padding = (4 - ((1 + pq_data_len) % 4)) % 4;
    offset += padding;

    /* Read fingerprints: Vector<long> */
    if (offset + 8 <= recv_len) {
        uint32_t vec_constructor;
        int32_t vec_count;
        memcpy(&vec_constructor, recv_buf + offset, 4); offset += 4;
        if (vec_constructor == TG_CONSTRUCTOR_VECTOR) {
            memcpy(&vec_count, recv_buf + offset, 4); offset += 4;
            if (vec_count > 0 && vec_count <= 8) {
                out_respq->fingerprint_count = (size_t)vec_count;
                for (i = 0; i < (size_t)vec_count && (offset + 8 <= recv_len); ++i) {
                    memcpy(&out_respq->fingerprints[i], recv_buf + offset, 8);
                    offset += 8;
                }
            }
        }
    }

    return CEGRAM_OK;
}
