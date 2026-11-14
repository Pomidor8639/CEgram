#include "cegram/mtproto.h"
#include "cegram/mini-gmp.h"
#include <time.h>

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

static int deserialize_tl_bytes(const uint8_t *src, size_t max_len, size_t *offset, uint8_t *dest, size_t max_dest, size_t *out_len) {
    size_t cur = *offset;
    size_t data_len = 0;
    size_t pad = 0;

    if (cur >= max_len) return CEGRAM_ERR_SCHEMA;

    uint8_t b0 = src[cur++];
    if (b0 < 254) {
        data_len = b0;
        pad = (4 - ((1 + data_len) % 4)) % 4;
    } else if (b0 == 0xfe) {
        if (cur + 3 > max_len) return CEGRAM_ERR_SCHEMA;
        data_len = (size_t)src[cur] | ((size_t)src[cur + 1] << 8) | ((size_t)src[cur + 2] << 16);
        cur += 3;
        pad = (4 - (data_len % 4)) % 4;
    } else {
        return CEGRAM_ERR_SCHEMA;
    }

    if (cur + data_len + pad > max_len || data_len > max_dest) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(dest, src + cur, data_len);
    cur += data_len + pad;
    *offset = cur;
    *out_len = data_len;
    return CEGRAM_OK;
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

int cegram_mtproto_decrypt_server_dh_inner(const cegram_server_dh_params_ok_t *server_dh,
                                           const uint8_t new_nonce[32],
                                           cegram_server_dh_inner_data_t *out_inner) {
    uint8_t key[32], iv[32];
    uint8_t dec_buf[1024];
    uint8_t calc_sha1[20];
    size_t offset = 20;
    uint32_t constructor = 0;

    if (!server_dh || !new_nonce || !out_inner || server_dh->encrypted_answer_len % 16 != 0) {
        return CEGRAM_ERR_GENERIC;
    }

    memset(out_inner, 0, sizeof(*out_inner));

    cegram_derive_tmp_aes_keys(new_nonce, server_dh->server_nonce, key, iv);
    cegram_aes_ige_decrypt(server_dh->encrypted_answer, dec_buf, server_dh->encrypted_answer_len, key, iv);

    if (offset + 4 > server_dh->encrypted_answer_len) return CEGRAM_ERR_SCHEMA;

    memcpy(&constructor, dec_buf + offset, 4); offset += 4;
    if (constructor != TG_CONSTRUCTOR_SERVER_DH_INNER_DATA) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_inner->nonce, dec_buf + offset, 16); offset += 16;
    memcpy(out_inner->server_nonce, dec_buf + offset, 16); offset += 16;
    memcpy(&out_inner->g, dec_buf + offset, 4); offset += 4;

    if (deserialize_tl_bytes(dec_buf, server_dh->encrypted_answer_len, &offset,
                             out_inner->dh_prime, sizeof(out_inner->dh_prime), &out_inner->dh_prime_len) != CEGRAM_OK) {
        return CEGRAM_ERR_SCHEMA;
    }

    if (deserialize_tl_bytes(dec_buf, server_dh->encrypted_answer_len, &offset,
                             out_inner->g_a, sizeof(out_inner->g_a), &out_inner->g_a_len) != CEGRAM_OK) {
        return CEGRAM_ERR_SCHEMA;
    }

    if (offset + 4 > server_dh->encrypted_answer_len) return CEGRAM_ERR_SCHEMA;
    memcpy(&out_inner->server_time, dec_buf + offset, 4); offset += 4;

    size_t inner_len = offset - 20;
    cegram_sha1(dec_buf + 20, inner_len, calc_sha1);
    if (memcmp(calc_sha1, dec_buf, 20) != 0) {
        return CEGRAM_ERR_CRYPTO;
    }

    return CEGRAM_OK;
}

int cegram_mtproto_complete_dh(cegram_transport_t *t,
                              const uint8_t nonce[16],
                              const uint8_t server_nonce[16],
                              const uint8_t new_nonce[32],
                              const cegram_server_dh_inner_data_t *server_dh_inner,
                              cegram_session_t *out_session) {
    uint8_t b_bytes[256];
    uint8_t gb_bytes[512];
    size_t gb_len = 0;
    uint8_t auth_key_bytes[256];
    size_t klen = 0;
    uint8_t temp[256];
    uint8_t inner[1024];
    size_t inner_len = 0;
    uint32_t constructor = TG_CONSTRUCTOR_CLIENT_DH_INNER_DATA;
    int64_t retry_id = 0;
    uint8_t sha1_inner[20];
    uint8_t to_encrypt[1024];
    size_t unpadded_len = 0;
    size_t pad_len = 0;
    size_t enc_len = 0;
    uint8_t key[32], iv[32];
    uint8_t encrypted_data[1024];
    uint8_t req[2048];
    size_t req_len = 0;
    uint32_t req_c = TG_CONSTRUCTOR_SET_CLIENT_DH_PARAMS;
    uint64_t auth_key_id = 0;
    uint64_t msg_id = cegram_generate_message_id();
    uint32_t msg_data_len = 0;
    uint8_t packet[2048];
    size_t packet_len = 0;
    uint8_t recv_buf[512];
    size_t recv_len = 0;
    size_t offset = 0;
    uint32_t resp_c = 0;
    uint8_t sha1_auth[20];
    uint8_t hash_buf[41];
    uint8_t check_sha1[20];
    uint8_t resp_hash[16];

    if (!t || !nonce || !server_nonce || !new_nonce || !server_dh_inner || !out_session) {
        return CEGRAM_ERR_GENERIC;
    }

    memset(out_session, 0, sizeof(*out_session));

    if (cegram_random_bytes(b_bytes, 256) != CEGRAM_OK) {
        return CEGRAM_ERR_CRYPTO;
    }

    mpz_t p, g, ga, gb, b, auth_key;
    mpz_init(p);
    mpz_init(g);
    mpz_init(ga);
    mpz_init(gb);
    mpz_init(b);
    mpz_init(auth_key);

    mpz_import(p, server_dh_inner->dh_prime_len, 1, 1, 1, 0, server_dh_inner->dh_prime);
    mpz_set_si(g, server_dh_inner->g);
    mpz_import(ga, server_dh_inner->g_a_len, 1, 1, 1, 0, server_dh_inner->g_a);
    mpz_import(b, 256, 1, 1, 1, 0, b_bytes);

    mpz_powm(gb, g, b, p);
    mpz_powm(auth_key, ga, b, p);

    mpz_export(gb_bytes, &gb_len, 1, 1, 1, 0, gb);

    memset(auth_key_bytes, 0, 256);
    mpz_export(temp, &klen, 1, 1, 1, 0, auth_key);
    if (klen <= 256) {
        memcpy(auth_key_bytes + (256 - klen), temp, klen);
    } else {
        mpz_clear(p); mpz_clear(g); mpz_clear(ga); mpz_clear(gb); mpz_clear(b); mpz_clear(auth_key);
        return CEGRAM_ERR_CRYPTO;
    }

    mpz_clear(p);
    mpz_clear(g);
    mpz_clear(ga);
    mpz_clear(gb);
    mpz_clear(b);
    mpz_clear(auth_key);

    memcpy(inner + inner_len, &constructor, 4); inner_len += 4;
    memcpy(inner + inner_len, nonce, 16); inner_len += 16;
    memcpy(inner + inner_len, server_nonce, 16); inner_len += 16;
    memcpy(inner + inner_len, &retry_id, 8); inner_len += 8;
    inner_len += serialize_tl_bytes(inner + inner_len, gb_bytes, gb_len);

    cegram_sha1(inner, inner_len, sha1_inner);
    memcpy(to_encrypt, sha1_inner, 20);
    memcpy(to_encrypt + 20, inner, inner_len);
    unpadded_len = 20 + inner_len;
    pad_len = (16 - (unpadded_len % 16)) % 16;
    if (pad_len > 0) {
        cegram_random_bytes(to_encrypt + unpadded_len, pad_len);
    }
    enc_len = unpadded_len + pad_len;

    cegram_derive_tmp_aes_keys(new_nonce, server_nonce, key, iv);
    cegram_aes_ige_encrypt(to_encrypt, encrypted_data, enc_len, key, iv);

    memcpy(req + req_len, &req_c, 4); req_len += 4;
    memcpy(req + req_len, nonce, 16); req_len += 16;
    memcpy(req + req_len, server_nonce, 16); req_len += 16;
    req_len += serialize_tl_bytes(req + req_len, encrypted_data, enc_len);

    msg_data_len = (uint32_t)req_len;
    memcpy(packet + packet_len, &auth_key_id, 8); packet_len += 8;
    memcpy(packet + packet_len, &msg_id, 8); packet_len += 8;
    memcpy(packet + packet_len, &msg_data_len, 4); packet_len += 4;
    memcpy(packet + packet_len, req, req_len); packet_len += req_len;

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
    memcpy(&resp_c, recv_buf + offset, 4); offset += 4;
    if (resp_c != TG_CONSTRUCTOR_DH_GEN_OK) {
        return CEGRAM_ERR_SCHEMA;
    }

    offset += 16;
    offset += 16;
    memcpy(resp_hash, recv_buf + offset, 16); offset += 16;

    cegram_sha1(auth_key_bytes, 256, sha1_auth);

    memcpy(hash_buf, new_nonce, 32);
    hash_buf[32] = 0x01;
    memcpy(hash_buf + 33, sha1_auth, 8);
    cegram_sha1(hash_buf, 41, check_sha1);

    if (memcmp(check_sha1 + 4, resp_hash, 16) != 0) {
        return CEGRAM_ERR_CRYPTO;
    }

    memcpy(out_session->auth_key, auth_key_bytes, 256);
    memcpy(&out_session->auth_key_id, sha1_auth + 12, 8);
    out_session->time_offset = server_dh_inner->server_time - (int32_t)time(NULL);

    return CEGRAM_OK;
}
