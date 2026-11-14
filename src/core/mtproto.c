#include "cegram/mtproto.h"
#include "cegram/mini-gmp.h"
#include <time.h>
#include <stdio.h>

int cegram_session_save(const cegram_session_t *session, const char *filepath) {
    FILE *fp;
    uint32_t magic = 0x53474543;
    uint32_t ver = 1;

    if (!session || !filepath) return CEGRAM_ERR_GENERIC;
    fp = fopen(filepath, "wb");
    if (!fp) return CEGRAM_ERR_GENERIC;

    fwrite(&magic, 4, 1, fp);
    fwrite(&ver, 4, 1, fp);
    fwrite(session->auth_key, 256, 1, fp);
    fwrite(&session->auth_key_id, 8, 1, fp);
    fwrite(&session->server_salt, 8, 1, fp);
    fwrite(&session->session_id, 8, 1, fp);
    fwrite(&session->time_offset, 4, 1, fp);
    fwrite(&session->seq_no, 4, 1, fp);

    fclose(fp);
    return CEGRAM_OK;
}

int cegram_session_load(cegram_session_t *session, const char *filepath) {
    FILE *fp;
    uint32_t magic = 0;
    uint32_t ver = 0;

    if (!session || !filepath) return CEGRAM_ERR_GENERIC;
    fp = fopen(filepath, "rb");
    if (!fp) return CEGRAM_ERR_GENERIC;

    if (fread(&magic, 4, 1, fp) != 1 || magic != 0x53474543) {
        fclose(fp);
        return CEGRAM_ERR_SCHEMA;
    }
    if (fread(&ver, 4, 1, fp) != 1 || ver != 1) {
        fclose(fp);
        return CEGRAM_ERR_SCHEMA;
    }
    if (fread(session->auth_key, 256, 1, fp) != 1) {
        fclose(fp);
        return CEGRAM_ERR_SCHEMA;
    }
    if (fread(&session->auth_key_id, 8, 1, fp) != 1) {
        fclose(fp);
        return CEGRAM_ERR_SCHEMA;
    }
    if (fread(&session->server_salt, 8, 1, fp) != 1) {
        fclose(fp);
        return CEGRAM_ERR_SCHEMA;
    }
    if (fread(&session->session_id, 8, 1, fp) != 1) {
        fclose(fp);
        return CEGRAM_ERR_SCHEMA;
    }
    if (fread(&session->time_offset, 4, 1, fp) != 1) {
        fclose(fp);
        return CEGRAM_ERR_SCHEMA;
    }
    if (fread(&session->seq_no, 4, 1, fp) != 1) {
        fclose(fp);
        return CEGRAM_ERR_SCHEMA;
    }

    fclose(fp);
    return CEGRAM_OK;
}

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
        for (i = 0; i < len; ++i) dest[written++] = src[i];
        pad = (4 - ((1 + len) % 4)) % 4;
        for (i = 0; i < pad; ++i) dest[written++] = 0x00;
    } else {
        dest[written++] = 0xfe;
        dest[written++] = (uint8_t)(len & 0xff);
        dest[written++] = (uint8_t)((len >> 8) & 0xff);
        dest[written++] = (uint8_t)((len >> 16) & 0xff);
        for (i = 0; i < len; ++i) dest[written++] = src[i];
        pad = (4 - (len % 4)) % 4;
        for (i = 0; i < pad; ++i) dest[written++] = 0x00;
    }
    return written;
}

static int deserialize_tl_bytes(const uint8_t *src, size_t max_len, size_t *offset,
                                uint8_t *out_data, size_t out_max, size_t *out_len) {
    size_t off = *offset;
    size_t data_len = 0;
    size_t pad = 0;

    if (off >= max_len) return CEGRAM_ERR_SCHEMA;

    if (src[off] < 254) {
        data_len = src[off++];
        pad = (4 - ((1 + data_len) % 4)) % 4;
    } else if (src[off] == 0xfe) {
        off++;
        if (off + 3 > max_len) return CEGRAM_ERR_SCHEMA;
        data_len = (size_t)src[off] | ((size_t)src[off + 1] << 8) | ((size_t)src[off + 2] << 16);
        off += 3;
        pad = (4 - (data_len % 4)) % 4;
    } else {
        return CEGRAM_ERR_SCHEMA;
    }

    if (data_len > out_max || (off + data_len + pad > max_len)) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_data, src + off, data_len);
    off += data_len + pad;
    *out_len = data_len;
    *offset = off;
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
    uint8_t inner_data[512];
    size_t inner_len = 0;
    uint32_t inner_constructor = TG_CONSTRUCTOR_P_Q_INNER_DATA_DC;
    uint8_t p_be[4], q_be[4];
    uint8_t rsa_encrypted[256];
    uint8_t req_body[1024];
    size_t req_len = 0;
    uint32_t req_constructor = TG_CONSTRUCTOR_REQ_DH_PARAMS;
    uint8_t packet[2048];
    size_t packet_len = 0;
    uint64_t auth_key_id = 0;
    uint64_t msg_id = cegram_generate_message_id();
    uint32_t msg_data_len = 0;
    uint8_t recv_buf[2048];
    size_t recv_len = 0;
    size_t offset = 0;
    uint32_t resp_constructor;
    uint8_t ans_first;
    size_t ans_data_len = 0;

    if (!t || !nonce || !server_nonce || !new_nonce || !key || !out_dh) {
        return CEGRAM_ERR_GENERIC;
    }

    memset(out_dh, 0, sizeof(*out_dh));

    p_be[0] = (uint8_t)((p >> 24) & 0xff);
    p_be[1] = (uint8_t)((p >> 16) & 0xff);
    p_be[2] = (uint8_t)((p >> 8) & 0xff);
    p_be[3] = (uint8_t)(p & 0xff);

    q_be[0] = (uint8_t)((q >> 24) & 0xff);
    q_be[1] = (uint8_t)((q >> 16) & 0xff);
    q_be[2] = (uint8_t)((q >> 8) & 0xff);
    q_be[3] = (uint8_t)(q & 0xff);

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

    return CEGRAM_OK;
}

int cegram_mtproto_complete_dh(cegram_transport_t *t,
                              const uint8_t nonce[16],
                              const uint8_t server_nonce[16],
                              const uint8_t new_nonce[32],
                              const cegram_server_dh_inner_data_t *server_dh_inner,
                              cegram_session_t *out_session) {
    mpz_t p, g, g_a, b, g_b, auth_key;
    uint8_t b_bytes[256];
    uint8_t g_b_bytes[256];
    size_t g_b_len = 0;
    uint8_t auth_key_bytes[256];
    size_t auth_key_len = 0;
    uint8_t inner_plain[1024];
    size_t inner_len = 0;
    uint32_t inner_ctor = TG_CONSTRUCTOR_CLIENT_DH_INNER_DATA;
    uint8_t sha1_inner[20];
    uint8_t to_encrypt[1024];
    size_t to_encrypt_len = 0;
    size_t pad_len = 0;
    uint8_t key[32], iv[32];
    uint8_t encrypted_data[1024];
    uint8_t set_dh_req[2048];
    size_t set_dh_len = 0;
    uint32_t set_dh_ctor = TG_CONSTRUCTOR_SET_CLIENT_DH_PARAMS;
    uint8_t packet[2048];
    size_t packet_len = 0;
    uint64_t null_auth_key_id = 0;
    uint64_t msg_id = cegram_generate_message_id();
    uint32_t msg_data_len;
    uint8_t recv_buf[512];
    size_t recv_len = 0;
    size_t offset = 0;
    uint32_t resp_ctor = 0;
    uint8_t resp_hash[16];
    uint8_t sha1_auth[20];
    uint8_t hash_buf[64];
    uint8_t check_sha1[20];

    if (!t || !nonce || !server_nonce || !new_nonce || !server_dh_inner || !out_session) {
        return CEGRAM_ERR_GENERIC;
    }

    memset(out_session, 0, sizeof(*out_session));

    mpz_init(p);
    mpz_init(g);
    mpz_init(g_a);
    mpz_init(b);
    mpz_init(g_b);
    mpz_init(auth_key);

    mpz_import(p, server_dh_inner->dh_prime_len, 1, 1, 1, 0, server_dh_inner->dh_prime);
    mpz_set_ui(g, (unsigned long)server_dh_inner->g);
    mpz_import(g_a, server_dh_inner->g_a_len, 1, 1, 1, 0, server_dh_inner->g_a);

    cegram_random_bytes(b_bytes, 256);
    mpz_import(b, 256, 1, 1, 1, 0, b_bytes);

    mpz_powm(g_b, g, b, p);
    mpz_powm(auth_key, g_a, b, p);

    memset(g_b_bytes, 0, sizeof(g_b_bytes));
    mpz_export(g_b_bytes, &g_b_len, 1, 1, 1, 0, g_b);

    memset(auth_key_bytes, 0, 256);
    {
        uint8_t temp[256];
        size_t klen = 0;
        mpz_export(temp, &klen, 1, 1, 1, 0, auth_key);
        if (klen <= 256) {
            memcpy(auth_key_bytes + (256 - klen), temp, klen);
        }
    }

    mpz_clear(p);
    mpz_clear(g);
    mpz_clear(g_a);
    mpz_clear(b);
    mpz_clear(g_b);
    mpz_clear(auth_key);

    memcpy(inner_plain + inner_len, &inner_ctor, 4); inner_len += 4;
    memcpy(inner_plain + inner_len, nonce, 16); inner_len += 16;
    memcpy(inner_plain + inner_len, server_nonce, 16); inner_len += 16;
    memset(inner_plain + inner_len, 0, 8); inner_len += 8;
    inner_len += serialize_tl_bytes(inner_plain + inner_len, g_b_bytes, g_b_len);

    cegram_sha1(inner_plain, inner_len, sha1_inner);

    memcpy(to_encrypt, sha1_inner, 20); to_encrypt_len += 20;
    memcpy(to_encrypt + to_encrypt_len, inner_plain, inner_len); to_encrypt_len += inner_len;
    pad_len = (16 - (to_encrypt_len % 16)) % 16;
    if (pad_len > 0) {
        cegram_random_bytes(to_encrypt + to_encrypt_len, pad_len);
        to_encrypt_len += pad_len;
    }

    cegram_derive_tmp_aes_keys(new_nonce, server_nonce, key, iv);
    cegram_aes_ige_encrypt(to_encrypt, encrypted_data, to_encrypt_len, key, iv);

    memcpy(set_dh_req + set_dh_len, &set_dh_ctor, 4); set_dh_len += 4;
    memcpy(set_dh_req + set_dh_len, nonce, 16); set_dh_len += 16;
    memcpy(set_dh_req + set_dh_len, server_nonce, 16); set_dh_len += 16;
    set_dh_len += serialize_tl_bytes(set_dh_req + set_dh_len, encrypted_data, to_encrypt_len);

    msg_data_len = (uint32_t)set_dh_len;
    memcpy(packet + packet_len, &null_auth_key_id, 8); packet_len += 8;
    memcpy(packet + packet_len, &msg_id, 8); packet_len += 8;
    memcpy(packet + packet_len, &msg_data_len, 4); packet_len += 4;
    memcpy(packet + packet_len, set_dh_req, set_dh_len); packet_len += set_dh_len;

    if (cegram_transport_send(t, packet, packet_len) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    if (cegram_transport_recv(t, recv_buf, sizeof(recv_buf), &recv_len) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    if (recv_len < 24) return CEGRAM_ERR_SCHEMA;
    offset = 20;
    memcpy(&resp_ctor, recv_buf + offset, 4); offset += 4;
    if (resp_ctor != TG_CONSTRUCTOR_DH_GEN_OK) {
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

int cegram_mtproto_send_encrypted_ex(cegram_transport_t *t,
                                     cegram_session_t *session,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     uint64_t *out_msg_id) {
    uint8_t plaintext[4096];
    uint8_t hash_buf[4096];
    uint8_t msg_key_large[32];
    uint8_t msg_key[16];
    uint8_t aes_key[32], aes_iv[32];
    uint8_t encrypted_data[4096];
    uint8_t packet[4096];
    size_t header_len = 32;
    size_t pad_len;
    size_t plaintext_len;
    size_t packet_len = 0;
    uint64_t msg_id;
    int32_t current_seq_no;
    uint32_t msg_data_len;

    if (!t || !session || !payload || payload_len == 0 || (payload_len + 64 > sizeof(plaintext))) {
        return CEGRAM_ERR_GENERIC;
    }

    if (session->session_id == 0) {
        cegram_random_bytes((uint8_t *)&session->session_id, 8);
    }

    msg_id = cegram_generate_message_id();
    if (out_msg_id) {
        *out_msg_id = msg_id;
    }

    current_seq_no = session->seq_no * 2 + 1;
    session->seq_no++;
    msg_data_len = (uint32_t)payload_len;

    memcpy(plaintext, &session->server_salt, 8);
    memcpy(plaintext + 8, &session->session_id, 8);
    memcpy(plaintext + 16, &msg_id, 8);
    memcpy(plaintext + 24, &current_seq_no, 4);
    memcpy(plaintext + 28, &msg_data_len, 4);
    memcpy(plaintext + 32, payload, payload_len);

    pad_len = 16 - ((header_len + payload_len) % 16);
    if (pad_len < 12) pad_len += 16;
    cegram_random_bytes(plaintext + header_len + payload_len, pad_len);
    plaintext_len = header_len + payload_len + pad_len;

    memcpy(hash_buf, session->auth_key + 88, 32);
    memcpy(hash_buf + 32, plaintext, plaintext_len);
    cegram_sha256(hash_buf, 32 + plaintext_len, msg_key_large);
    memcpy(msg_key, msg_key_large + 8, 16);

    cegram_derive_msg_keys(session->auth_key, msg_key, 1, aes_key, aes_iv);
    cegram_aes_ige_encrypt(plaintext, encrypted_data, plaintext_len, aes_key, aes_iv);

    memcpy(packet, &session->auth_key_id, 8); packet_len += 8;
    memcpy(packet + packet_len, msg_key, 16); packet_len += 16;
    memcpy(packet + packet_len, encrypted_data, plaintext_len); packet_len += plaintext_len;

    return cegram_transport_send(t, packet, packet_len);
}

int cegram_mtproto_send_encrypted(cegram_transport_t *t,
                                  cegram_session_t *session,
                                  const uint8_t *payload,
                                  size_t payload_len) {
    return cegram_mtproto_send_encrypted_ex(t, session, payload, payload_len, NULL);
}

int cegram_mtproto_recv_encrypted(cegram_transport_t *t,
                                  cegram_session_t *session,
                                  uint8_t *out_payload,
                                  size_t max_payload_len,
                                  size_t *out_payload_len) {
    uint8_t recv_buf[4096];
    size_t recv_len = 0;
    uint8_t msg_key[16];
    uint8_t aes_key[32], aes_iv[32];
    uint8_t plaintext[4096];
    uint8_t hash_buf[4096];
    uint8_t msg_key_large[32];
    uint64_t auth_key_id;
    uint64_t server_salt;
    uint32_t msg_len;
    size_t cipher_len;

    if (!t || !session || !out_payload || !out_payload_len) {
        return CEGRAM_ERR_GENERIC;
    }

    if (cegram_transport_recv(t, recv_buf, sizeof(recv_buf), &recv_len) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    if (recv_len < 40) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(&auth_key_id, recv_buf, 8);
    if (auth_key_id != session->auth_key_id) {
        return CEGRAM_ERR_CRYPTO;
    }

    memcpy(msg_key, recv_buf + 8, 16);
    cipher_len = recv_len - 24;
    if (cipher_len % 16 != 0) {
        return CEGRAM_ERR_SCHEMA;
    }

    cegram_derive_msg_keys(session->auth_key, msg_key, 0, aes_key, aes_iv);
    cegram_aes_ige_decrypt(recv_buf + 24, plaintext, cipher_len, aes_key, aes_iv);

    memcpy(hash_buf, session->auth_key + 96, 32);
    memcpy(hash_buf + 32, plaintext, cipher_len);
    cegram_sha256(hash_buf, 32 + cipher_len, msg_key_large);

    if (memcmp(msg_key_large + 8, msg_key, 16) != 0) {
        return CEGRAM_ERR_CRYPTO;
    }

    memcpy(&server_salt, plaintext, 8);
    session->server_salt = server_salt;

    memcpy(&msg_len, plaintext + 28, 4);
    if (msg_len > max_payload_len || (32 + msg_len > cipher_len)) {
        return CEGRAM_ERR_SCHEMA;
    }

    memcpy(out_payload, plaintext + 32, msg_len);
    *out_payload_len = (size_t)msg_len;

    return CEGRAM_OK;
}

int cegram_mtproto_invoke(cegram_transport_t *t,
                          cegram_session_t *session,
                          const uint8_t *req_payload,
                          size_t req_len,
                          uint8_t *out_resp,
                          size_t max_resp_len,
                          size_t *out_resp_len) {
    uint8_t resp_buf[4096];
    size_t resp_len = 0;
    uint64_t sent_msg_id = 0;
    int resend_attempts = 0;
    int res;

    if (!t || !session || !req_payload || !out_resp || !out_resp_len) {
        return CEGRAM_ERR_GENERIC;
    }

    while (resend_attempts < 3) {
        int recv_attempts = 0;
        int need_resend = 0;

        resend_attempts++;
        res = cegram_mtproto_send_encrypted_ex(t, session, req_payload, req_len, &sent_msg_id);
        if (res != CEGRAM_OK) {
            return res;
        }

        while (recv_attempts < 10) {
            recv_attempts++;
            res = cegram_mtproto_recv_encrypted(t, session, resp_buf, sizeof(resp_buf), &resp_len);
            if (res != CEGRAM_OK) {
                break;
            }

            if (resp_len < 4) continue;
            uint32_t constructor = 0;
            memcpy(&constructor, resp_buf, 4);

            if (constructor == TG_CONSTRUCTOR_BAD_SERVER_SALT) {
                if (resp_len >= 28) {
                    uint64_t new_salt = 0;
                    memcpy(&new_salt, resp_buf + 20, 8);
                    session->server_salt = new_salt;
                    need_resend = 1;
                    break;
                }
            }

            if (constructor == TG_CONSTRUCTOR_NEW_SESSION_CREATED && resp_len >= 28) {
                uint64_t new_salt = 0;
                memcpy(&new_salt, resp_buf + 20, 8);
                session->server_salt = new_salt;
                continue;
            }

            if (constructor == TG_CONSTRUCTOR_RPC_RESULT && resp_len >= 12) {
                uint64_t req_id = 0;
                memcpy(&req_id, resp_buf + 4, 8);
                if (sent_msg_id == 0 || req_id == sent_msg_id) {
                    size_t result_len = resp_len - 12;
                    if (result_len > max_resp_len) return CEGRAM_ERR_BUFFER_TOO_SMALL;
                    memcpy(out_resp, resp_buf + 12, result_len);
                    *out_resp_len = result_len;
                    return CEGRAM_OK;
                }
                continue;
            }

            if (constructor == TG_CONSTRUCTOR_MSG_CONTAINER && resp_len >= 8) {
                uint32_t count = 0;
                memcpy(&count, resp_buf + 4, 4);
                size_t off = 8;
                int found_result = 0;
                uint32_t i;
                for (i = 0; i < count && off + 16 <= resp_len; i++) {
                    uint32_t inner_bytes = 0;
                    off += 8;
                    off += 4;
                    memcpy(&inner_bytes, resp_buf + off, 4); off += 4;
                    if (off + inner_bytes > resp_len) break;
                    if (inner_bytes >= 4) {
                        uint32_t inner_ctor = 0;
                        memcpy(&inner_ctor, resp_buf + off, 4);
                        if (inner_ctor == TG_CONSTRUCTOR_NEW_SESSION_CREATED && inner_bytes >= 28) {
                            uint64_t new_salt = 0;
                            memcpy(&new_salt, resp_buf + off + 20, 8);
                            session->server_salt = new_salt;
                        } else if (inner_ctor == TG_CONSTRUCTOR_BAD_SERVER_SALT && inner_bytes >= 28) {
                            uint64_t new_salt = 0;
                            memcpy(&new_salt, resp_buf + off + 20, 8);
                            session->server_salt = new_salt;
                            need_resend = 1;
                            break;
                        } else if (inner_ctor == TG_CONSTRUCTOR_RPC_RESULT && inner_bytes >= 12) {
                            uint64_t req_id = 0;
                            memcpy(&req_id, resp_buf + off + 4, 8);
                            if (sent_msg_id == 0 || req_id == sent_msg_id) {
                                size_t result_len = inner_bytes - 12;
                                if (result_len > max_resp_len) return CEGRAM_ERR_BUFFER_TOO_SMALL;
                                memcpy(out_resp, resp_buf + off + 12, result_len);
                                *out_resp_len = result_len;
                                found_result = 1;
                                break;
                            }
                        }
                    }
                    off += inner_bytes;
                }
                if (need_resend) break;
                if (found_result) return CEGRAM_OK;
                continue;
            }

            if (sent_msg_id == 0) {
                if (resp_len > max_resp_len) return CEGRAM_ERR_BUFFER_TOO_SMALL;
                memcpy(out_resp, resp_buf, resp_len);
                *out_resp_len = resp_len;
                return CEGRAM_OK;
            }
        }

        if (!need_resend) break;
    }

    return CEGRAM_ERR_NETWORK;
}

int cegram_auth_send_code(cegram_transport_t *t,
                          cegram_session_t *session,
                          const char *phone_number,
                          int32_t api_id,
                          const char *api_hash,
                          cegram_auth_sent_code_t *out_sent_code,
                          cegram_rpc_error_t *out_error) {
    uint8_t raw_req[512];
    size_t raw_len = 0;
    uint8_t req[1024];
    size_t req_len = 0;
    uint8_t resp[2048];
    size_t resp_len = 0;
    uint32_t ctor = TG_CONSTRUCTOR_AUTH_SEND_CODE;
    uint32_t settings_ctor = TG_CONSTRUCTOR_CODE_SETTINGS;
    uint32_t settings_flags = 0;
    int res;

    if (!t || !session || !phone_number || !api_hash) return CEGRAM_ERR_GENERIC;
    if (out_error) memset(out_error, 0, sizeof(*out_error));

    cegram_tl_write_uint32(raw_req, sizeof(raw_req), &raw_len, ctor);
    cegram_tl_write_string(raw_req, sizeof(raw_req), &raw_len, phone_number);
    cegram_tl_write_uint32(raw_req, sizeof(raw_req), &raw_len, (uint32_t)api_id);
    cegram_tl_write_string(raw_req, sizeof(raw_req), &raw_len, api_hash);
    cegram_tl_write_uint32(raw_req, sizeof(raw_req), &raw_len, settings_ctor);
    cegram_tl_write_uint32(raw_req, sizeof(raw_req), &raw_len, settings_flags);

    cegram_tl_write_uint32(req, sizeof(req), &req_len, TG_CONSTRUCTOR_INVOKE_WITH_LAYER);
    cegram_tl_write_uint32(req, sizeof(req), &req_len, 184);
    memcpy(req + req_len, raw_req, raw_len);
    req_len += raw_len;

    res = cegram_mtproto_invoke(t, session, req, req_len, resp, sizeof(resp), &resp_len);
    if (res != CEGRAM_OK) return res;

    if (resp_len < 4) return CEGRAM_ERR_SCHEMA;
    size_t off = 0;
    uint32_t resp_ctor = 0;
    cegram_tl_read_uint32(resp, resp_len, &off, &resp_ctor);

    if (resp_ctor == TG_CONSTRUCTOR_RPC_ERROR) {
        if (out_error) {
            cegram_tl_read_uint32(resp, resp_len, &off, (uint32_t *)&out_error->error_code);
            cegram_tl_read_string(resp, resp_len, &off, out_error->error_message, sizeof(out_error->error_message));
        }
        return CEGRAM_ERR_SCHEMA;
    }

    if (resp_ctor == TG_CONSTRUCTOR_AUTH_SENT_CODE) {
        if (out_sent_code) {
            memset(out_sent_code, 0, sizeof(*out_sent_code));
            uint32_t flags = 0;
            uint32_t sent_code_type_ctor = 0;
            cegram_tl_read_uint32(resp, resp_len, &off, &flags);
            cegram_tl_read_uint32(resp, resp_len, &off, &sent_code_type_ctor);
            if (sent_code_type_ctor == 0x3dbb5986) {
                out_sent_code->is_app_code = 1;
                uint32_t code_len = 0;
                cegram_tl_read_uint32(resp, resp_len, &off, &code_len);
            } else if (sent_code_type_ctor == 0xc000bba2) {
                out_sent_code->is_app_code = 0;
                uint32_t code_len = 0;
                cegram_tl_read_uint32(resp, resp_len, &off, &code_len);
            }
            cegram_tl_read_string(resp, resp_len, &off, out_sent_code->phone_code_hash, sizeof(out_sent_code->phone_code_hash));
            if (flags & 2) {
                uint32_t next_type = 0;
                cegram_tl_read_uint32(resp, resp_len, &off, &next_type);
            }
            if (flags & 4) {
                cegram_tl_read_uint32(resp, resp_len, &off, (uint32_t *)&out_sent_code->timeout);
            }
        }
        return CEGRAM_OK;
    }

    return CEGRAM_ERR_SCHEMA;
}

int cegram_auth_sign_in(cegram_transport_t *t,
                        cegram_session_t *session,
                        const char *phone_number,
                        const char *phone_code_hash,
                        const char *phone_code,
                        cegram_user_t *out_user,
                        cegram_rpc_error_t *out_error) {
    uint8_t raw_req[1024];
    size_t raw_len = 0;
    uint8_t req[1024];
    size_t req_len = 0;
    uint8_t resp[4096];
    size_t resp_len = 0;
    uint32_t ctor = TG_CONSTRUCTOR_AUTH_SIGN_IN;
    uint32_t flags = 1;
    int res;

    if (!t || !session || !phone_number || !phone_code_hash || !phone_code) return CEGRAM_ERR_GENERIC;
    if (out_error) memset(out_error, 0, sizeof(*out_error));

    cegram_tl_write_uint32(raw_req, sizeof(raw_req), &raw_len, ctor);
    cegram_tl_write_uint32(raw_req, sizeof(raw_req), &raw_len, flags);
    cegram_tl_write_string(raw_req, sizeof(raw_req), &raw_len, phone_number);
    cegram_tl_write_string(raw_req, sizeof(raw_req), &raw_len, phone_code_hash);
    cegram_tl_write_string(raw_req, sizeof(raw_req), &raw_len, phone_code);

    cegram_tl_write_uint32(req, sizeof(req), &req_len, TG_CONSTRUCTOR_INVOKE_WITH_LAYER);
    cegram_tl_write_uint32(req, sizeof(req), &req_len, 184);
    memcpy(req + req_len, raw_req, raw_len);
    req_len += raw_len;

    res = cegram_mtproto_invoke(t, session, req, req_len, resp, sizeof(resp), &resp_len);
    if (res != CEGRAM_OK) return res;

    if (resp_len < 4) return CEGRAM_ERR_SCHEMA;
    size_t off = 0;
    uint32_t resp_ctor = 0;
    cegram_tl_read_uint32(resp, resp_len, &off, &resp_ctor);

    if (resp_ctor == TG_CONSTRUCTOR_RPC_ERROR) {
        if (out_error) {
            cegram_tl_read_uint32(resp, resp_len, &off, (uint32_t *)&out_error->error_code);
            cegram_tl_read_string(resp, resp_len, &off, out_error->error_message, sizeof(out_error->error_message));
        }
        return CEGRAM_ERR_SCHEMA;
    }

    if (resp_ctor == TG_CONSTRUCTOR_AUTH_AUTHORIZATION || resp_ctor == TG_CONSTRUCTOR_AUTH_AUTHORIZATION_OLD) {
        if (out_user) {
            memset(out_user, 0, sizeof(*out_user));
            uint32_t auth_flags = 0;
            cegram_tl_read_uint32(resp, resp_len, &off, &auth_flags);
            if (auth_flags & 1) {
                uint32_t tmp_sess = 0;
                cegram_tl_read_uint32(resp, resp_len, &off, &tmp_sess);
            }
            uint32_t user_ctor = 0;
            cegram_tl_read_uint32(resp, resp_len, &off, &user_ctor);
            if (user_ctor == TG_CONSTRUCTOR_USER) {
                uint32_t uflags = 0;
                cegram_tl_read_uint32(resp, resp_len, &off, &uflags);
                cegram_tl_read_uint64(resp, resp_len, &off, &out_user->user_id);
                uint64_t access_hash = 0;
                if (uflags & (1 << 0)) {
                    cegram_tl_read_uint64(resp, resp_len, &off, &access_hash);
                }
                if (uflags & (1 << 1)) {
                    cegram_tl_read_string(resp, resp_len, &off, out_user->first_name, sizeof(out_user->first_name));
                }
                if (uflags & (1 << 2)) {
                    cegram_tl_read_string(resp, resp_len, &off, out_user->last_name, sizeof(out_user->last_name));
                }
                if (uflags & (1 << 3)) {
                    cegram_tl_read_string(resp, resp_len, &off, out_user->username, sizeof(out_user->username));
                }
                if (uflags & (1 << 4)) {
                    cegram_tl_read_string(resp, resp_len, &off, out_user->phone, sizeof(out_user->phone));
                }
            }
        }
        return CEGRAM_OK;
    }

    return CEGRAM_ERR_SCHEMA;
}

int cegram_mtproto_wrap_init_connection(uint8_t *buf, size_t max_buf_len, size_t *out_len,
                                        int32_t layer, int32_t api_id,
                                        const char *device_model,
                                        const char *system_version,
                                        const char *app_version,
                                        const char *lang_code,
                                        const uint8_t *inner_query, size_t inner_query_len) {
    size_t off = 0;
    uint32_t ctor_invoke = TG_CONSTRUCTOR_INVOKE_WITH_LAYER;
    uint32_t ctor_init = TG_CONSTRUCTOR_INIT_CONNECTION;
    uint32_t flags = 0;

    if (!buf || !out_len || !inner_query) return CEGRAM_ERR_GENERIC;

    cegram_tl_write_uint32(buf, max_buf_len, &off, ctor_invoke);
    cegram_tl_write_uint32(buf, max_buf_len, &off, (uint32_t)layer);
    cegram_tl_write_uint32(buf, max_buf_len, &off, ctor_init);
    cegram_tl_write_uint32(buf, max_buf_len, &off, flags);
    cegram_tl_write_uint32(buf, max_buf_len, &off, (uint32_t)api_id);
    cegram_tl_write_string(buf, max_buf_len, &off, device_model ? device_model : "Windows CE Device");
    cegram_tl_write_string(buf, max_buf_len, &off, system_version ? system_version : "Windows CE 6.0");
    cegram_tl_write_string(buf, max_buf_len, &off, app_version ? app_version : "1.0.0");
    cegram_tl_write_string(buf, max_buf_len, &off, lang_code ? lang_code : "en");
    cegram_tl_write_string(buf, max_buf_len, &off, "tdesktop");
    cegram_tl_write_string(buf, max_buf_len, &off, lang_code ? lang_code : "en");

    if (off + inner_query_len > max_buf_len) return CEGRAM_ERR_BUFFER_TOO_SMALL;
    memcpy(buf + off, inner_query, inner_query_len);
    off += inner_query_len;

    *out_len = off;
    return CEGRAM_OK;
}
