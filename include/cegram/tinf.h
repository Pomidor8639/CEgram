#ifndef CEGRAM_TINF_H
#define CEGRAM_TINF_H

#ifdef __cplusplus
extern "C" {
#endif

#define TINF_OK          0
#define TINF_DATA_ERROR -3
#define TINF_BUF_ERROR  -5

int tinf_uncompress(void *dest, unsigned int *destLen,
                    const void *source, unsigned int sourceLen);

int tinf_gzip_uncompress(void *dest, unsigned int *destLen,
                         const void *source, unsigned int sourceLen);

unsigned int tinf_crc32(const void *data, unsigned int length);

#ifdef __cplusplus
}
#endif

#endif
