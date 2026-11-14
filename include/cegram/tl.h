#ifndef CEGRAM_TL_H
#define CEGRAM_TL_H

#include "common.h"

int cegram_tl_write_uint32(uint8_t *buf, size_t max_len, size_t *offset, uint32_t val);
int cegram_tl_write_uint64(uint8_t *buf, size_t max_len, size_t *offset, uint64_t val);
int cegram_tl_write_bytes(uint8_t *buf, size_t max_len, size_t *offset, const uint8_t *data, size_t len);
int cegram_tl_write_string(uint8_t *buf, size_t max_len, size_t *offset, const char *str);

int cegram_tl_read_uint32(const uint8_t *buf, size_t len, size_t *offset, uint32_t *out_val);
int cegram_tl_read_uint64(const uint8_t *buf, size_t len, size_t *offset, uint64_t *out_val);
int cegram_tl_read_bytes(const uint8_t *buf, size_t len, size_t *offset, uint8_t *out_data, size_t max_out_len, size_t *out_len);
int cegram_tl_read_string(const uint8_t *buf, size_t len, size_t *offset, char *out_str, size_t max_str_len);

#endif
