#include "cegram/mtproto.h"

int cegram_mtproto_send_req_pq_multi(cegram_transport_t *t, const uint8_t nonce[16], cegram_respq_t *out_respq) {
    uint8_t packet[64];
    uint8_t recv_buf[512];
    size_t recv_len = 0;
    uint64_t auth_key_id = 0;
    uint64_t msg_id = cegram_generate_message_id();
    uint32_t msg_data_len = 4 + 16;
    uint32_t constructor = TG_CONSTRUCTOR_REQ_PQ_MULTI;
    size_t offset = 0;
    size_t i;
    uint32_t resp_constructor;
    uint8_t pq_first_byte;
    size_t pq_data_len = 0;
    size_t padding;

    if (!t || !nonce || !out_respq) {
        return CEGRAM_ERR_GENERIC;
    }

    memset(out_respq, 0, sizeof(*out_respq));

    memcpy(packet + offset, &auth_key_id, 8); offset += 8;
    memcpy(packet + offset, &msg_id, 8); offset += 8;
    memcpy(packet + offset, &msg_data_len, 4); offset += 4;
    memcpy(packet + offset, &constructor, 4); offset += 4;
    memcpy(packet + offset, nonce, 16); offset += 16;

    if (cegram_transport_send(t, packet, offset) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    if (cegram_transport_recv(t, recv_buf, sizeof(recv_buf), &recv_len) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    if (recv_len < 24) {
        return CEGRAM_ERR_SCHEMA;
    }

    offset = 20;

    memcpy(&resp_constructor, recv_buf + offset, 4); offset += 4;
    if (resp_constructor != TG_CONSTRUCTOR_RESPQ) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_respq->nonce, recv_buf + offset, 16); offset += 16;
    if (memcmp(out_respq->nonce, nonce, 16) != 0) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_respq->server_nonce, recv_buf + offset, 16); offset += 16;

    pq_first_byte = recv_buf[offset++];
    if (pq_first_byte <= 253) {
        pq_data_len = pq_first_byte;
    } else {
        return CEGRAM_ERR_SCHEMA;
    }

    if (pq_data_len > sizeof(out_respq->pq) || (offset + pq_data_len > recv_len)) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_respq->pq, recv_buf + offset, pq_data_len);
    out_respq->pq_len = pq_data_len;
    offset += pq_data_len;

    padding = (4 - ((1 + pq_data_len) % 4)) % 4;
    offset += padding;

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

static size_t serialize_tl_bytes(uint8_t *dest, const uint8_t *src, size_t len) {
    size_t written = 0;
    size_t i, pad;

    if (len < 254) {
        dest[written++] = (uint8_t)len;
        memcpy(dest + written, src, len);
        written += len;
        pad = (4 - (written % 4)) % 4;
        for (i = 0; i < pad; ++i) {
            dest[written++] = 0;
        }
    } else {
        dest[written++] = 0xfe;
        dest[written++] = (uint8_t)(len & 0xff);
        dest[written++] = (uint8_t)((len >> 8) & 0xff);
        dest[written++] = (uint8_t)((len >> 16) & 0xff);
        memcpy(dest + written, src, len);
        written += len;
        pad = (4 - (written % 4)) % 4;
        for (i = 0; i < pad; ++i) {
            dest[written++] = 0;
        }
    }
    return written;
}

int cegram_mtproto_send_req_dh_params(cegram_transport_t *t,
                                      const uint8_t nonce[16],
                                      const uint8_t server_nonce[16],
                                      const uint8_t new_nonce[32],
                                      uint32_t p, uint32_t q,
                                      const uint8_t *pq_raw, size_t pq_len,
                                      const cegram_rsa_key_t *key,
                                      int dc_id,
                                      cegram_server_dh_params_ok_t *out_dh) {
    uint8_t inner_data[256];
    size_t inner_len = 0;
    uint32_t inner_constructor = TG_CONSTRUCTOR_P_Q_INNER_DATA_DC;
    uint8_t p_be[4], q_be[4];
    uint8_t rsa_encrypted[256];
    uint8_t req_body[1024];
    size_t req_len = 0;
    uint32_t req_constructor = TG_CONSTRUCTOR_REQ_DH_PARAMS;
    uint64_t auth_key_id = 0;
    uint64_t msg_id = cegram_generate_message_id();
    uint32_t msg_data_len;
    uint8_t packet[1024];
    size_t packet_len = 0;
    uint8_t recv_buf[2048];
    size_t recv_len = 0;
    size_t offset = 0;
    uint32_t resp_constructor;
    uint8_t ans_first;
    size_t ans_data_len = 0;

    if (!t || !nonce || !server_nonce || !new_nonce || !pq_raw || !key || !out_dh) {
        return CEGRAM_ERR_GENERIC;
    }

    memset(out_dh, 0, sizeof(*out_dh));

    p_be[0] = (uint8_t)((p >> 24) & 0xFF);
    p_be[1] = (uint8_t)((p >> 16) & 0xFF);
    p_be[2] = (uint8_t)((p >> 8) & 0xFF);
    p_be[3] = (uint8_t)(p & 0xFF);

    q_be[0] = (uint8_t)((q >> 24) & 0xFF);
    q_be[1] = (uint8_t)((q >> 16) & 0xFF);
    q_be[2] = (uint8_t)((q >> 8) & 0xFF);
    q_be[3] = (uint8_t)(q & 0xFF);

    memcpy(inner_data + inner_len, &inner_constructor, 4); inner_len += 4;
    inner_len += serialize_tl_bytes(inner_data + inner_len, pq_raw, pq_len);
    inner_len += serialize_tl_bytes(inner_data + inner_len, p_be, 4);
    inner_len += serialize_tl_bytes(inner_data + inner_len, q_be, 4);
    memcpy(inner_data + inner_len, nonce, 16); inner_len += 16;
    memcpy(inner_data + inner_len, server_nonce, 16); inner_len += 16;
    memcpy(inner_data + inner_len, new_nonce, 32); inner_len += 32;
    memcpy(inner_data + inner_len, &dc_id, 4); inner_len += 4;

    if (cegram_rsa_encrypt_pad(inner_data, inner_len, key, rsa_encrypted) != CEGRAM_OK) {
        return CEGRAM_ERR_CRYPTO;
    }

    memcpy(req_body + req_len, &req_constructor, 4); req_len += 4;
    memcpy(req_body + req_len, nonce, 16); req_len += 16;
    memcpy(req_body + req_len, server_nonce, 16); req_len += 16;
    req_len += serialize_tl_bytes(req_body + req_len, p_be, 4);
    req_len += serialize_tl_bytes(req_body + req_len, q_be, 4);
    memcpy(req_body + req_len, &key->fingerprint, 8); req_len += 8;
    req_len += serialize_tl_bytes(req_body + req_len, rsa_encrypted, 256);

    msg_data_len = (uint32_t)req_len;
    memcpy(packet + packet_len, &auth_key_id, 8); packet_len += 8;
    memcpy(packet + packet_len, &msg_id, 8); packet_len += 8;
    memcpy(packet + packet_len, &msg_data_len, 4); packet_len += 4;
    memcpy(packet + packet_len, req_body, req_len); packet_len += req_len;

    if (cegram_transport_send(t, packet, packet_len) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    if (cegram_transport_recv(t, recv_buf, sizeof(recv_buf), &recv_len) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    if (recv_len < 24) {
        return CEGRAM_ERR_SCHEMA;
    }

    offset = 20;

    memcpy(&resp_constructor, recv_buf + offset, 4); offset += 4;
    if (resp_constructor != TG_CONSTRUCTOR_SERVER_DH_PARAMS_OK) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_dh->nonce, recv_buf + offset, 16); offset += 16;
    memcpy(out_dh->server_nonce, recv_buf + offset, 16); offset += 16;

    ans_first = recv_buf[offset++];
    if (ans_first < 254) {
        ans_data_len = ans_first;
    } else if (ans_first == 0xfe) {
        ans_data_len = (size_t)recv_buf[offset] |
                       ((size_t)recv_buf[offset + 1] << 8) |
                       ((size_t)recv_buf[offset + 2] << 16);
        offset += 3;
    } else {
        return CEGRAM_ERR_SCHEMA;
    }

    if (ans_data_len > sizeof(out_dh->encrypted_answer) || (offset + ans_data_len > recv_len)) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_dh->encrypted_answer, recv_buf + offset, ans_data_len);
    out_dh->encrypted_answer_len = ans_data_len;

    return CEGRAM_OK;
}
