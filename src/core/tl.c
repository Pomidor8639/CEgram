#include "cegram/tl.h"

int cegram_tl_write_uint32(uint8_t *buf, size_t max_len, size_t *offset, uint32_t val) {
    if (!buf || !offset || *offset + 4 > max_len) return CEGRAM_ERR_BUFFER_TOO_SMALL;
    memcpy(buf + *offset, &val, 4);
    *offset += 4;
    return CEGRAM_OK;
}

int cegram_tl_write_uint64(uint8_t *buf, size_t max_len, size_t *offset, uint64_t val) {
    if (!buf || !offset || *offset + 8 > max_len) return CEGRAM_ERR_BUFFER_TOO_SMALL;
    memcpy(buf + *offset, &val, 8);
    *offset += 8;
    return CEGRAM_OK;
}

int cegram_tl_write_bytes(uint8_t *buf, size_t max_len, size_t *offset, const uint8_t *data, size_t len) {
    size_t pad;
    size_t total;
    if (!buf || !offset) return CEGRAM_ERR_GENERIC;

    if (len < 254) {
        pad = (4 - ((len + 1) % 4)) % 4;
        total = 1 + len + pad;
        if (*offset + total > max_len) return CEGRAM_ERR_BUFFER_TOO_SMALL;
        buf[(*offset)++] = (uint8_t)len;
        if (len > 0 && data) {
            memcpy(buf + *offset, data, len);
            *offset += len;
        }
        if (pad > 0) {
            memset(buf + *offset, 0, pad);
            *offset += pad;
        }
    } else {
        pad = (4 - (len % 4)) % 4;
        total = 4 + len + pad;
        if (*offset + total > max_len) return CEGRAM_ERR_BUFFER_TOO_SMALL;
        buf[(*offset)++] = 0xfe;
        buf[(*offset)++] = (uint8_t)(len & 0xff);
        buf[(*offset)++] = (uint8_t)((len >> 8) & 0xff);
        buf[(*offset)++] = (uint8_t)((len >> 16) & 0xff);
        if (len > 0 && data) {
            memcpy(buf + *offset, data, len);
            *offset += len;
        }
        if (pad > 0) {
            memset(buf + *offset, 0, pad);
            *offset += pad;
        }
    }
    return CEGRAM_OK;
}

int cegram_tl_write_string(uint8_t *buf, size_t max_len, size_t *offset, const char *str) {
    size_t len = str ? strlen(str) : 0;
    return cegram_tl_write_bytes(buf, max_len, offset, (const uint8_t *)str, len);
}

int cegram_tl_read_uint32(const uint8_t *buf, size_t len, size_t *offset, uint32_t *out_val) {
    if (!buf || !offset || !out_val || *offset + 4 > len) return CEGRAM_ERR_SCHEMA;
    memcpy(out_val, buf + *offset, 4);
    *offset += 4;
    return CEGRAM_OK;
}

int cegram_tl_read_uint64(const uint8_t *buf, size_t len, size_t *offset, uint64_t *out_val) {
    if (!buf || !offset || !out_val || *offset + 8 > len) return CEGRAM_ERR_SCHEMA;
    memcpy(out_val, buf + *offset, 8);
    *offset += 8;
    return CEGRAM_OK;
}

int cegram_tl_read_bytes(const uint8_t *buf, size_t len, size_t *offset, uint8_t *out_data, size_t max_out_len, size_t *out_len) {
    uint8_t first;
    size_t byte_len = 0;
    size_t pad = 0;

    if (!buf || !offset || !out_data || !out_len || *offset >= len) return CEGRAM_ERR_SCHEMA;

    first = buf[(*offset)++];
    if (first < 254) {
        byte_len = first;
        pad = (4 - ((byte_len + 1) % 4)) % 4;
    } else if (first == 0xfe) {
        if (*offset + 3 > len) return CEGRAM_ERR_SCHEMA;
        byte_len = (size_t)buf[*offset] | ((size_t)buf[*offset + 1] << 8) | ((size_t)buf[*offset + 2] << 16);
        *offset += 3;
        pad = (4 - (byte_len % 4)) % 4;
    } else {
        return CEGRAM_ERR_SCHEMA;
    }

    if (byte_len > max_out_len || *offset + byte_len + pad > len) return CEGRAM_ERR_SCHEMA;

    memcpy(out_data, buf + *offset, byte_len);
    *offset += byte_len + pad;
    *out_len = byte_len;
    return CEGRAM_OK;
}

int cegram_tl_read_string(const uint8_t *buf, size_t len, size_t *offset, char *out_str, size_t max_str_len) {
    size_t byte_len = 0;
    int res;
    if (!out_str || max_str_len == 0) return CEGRAM_ERR_GENERIC;
    res = cegram_tl_read_bytes(buf, len, offset, (uint8_t *)out_str, max_str_len - 1, &byte_len);
    if (res != CEGRAM_OK) return res;
    out_str[byte_len] = '\0';
    return CEGRAM_OK;
}
