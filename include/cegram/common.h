#ifndef CEGRAM_COMMON_H
#define CEGRAM_COMMON_H

#if defined(_WIN32_WCE) || defined(UNDER_CE)
    #define CEGRAM_PLATFORM_WINCE 1
#elif defined(_WIN32)
    #define CEGRAM_PLATFORM_WIN32 1
#else
    #define CEGRAM_PLATFORM_POSIX 1
#endif

#if defined(_MSC_VER) && (_MSC_VER < 1600)
    typedef unsigned char      uint8_t;
    typedef signed char        int8_t;
    typedef unsigned short     uint16_t;
    typedef signed short       int16_t;
    typedef unsigned int       uint32_t;
    typedef signed int         int32_t;
    typedef unsigned __int64   uint64_t;
    typedef signed __int64     int64_t;
#else
    #include <stdint.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CEGRAM_OK          0
#define CEGRAM_ERR_GENERIC -1
#define CEGRAM_ERR_NETWORK -2
#define CEGRAM_ERR_CRYPTO  -3
#define CEGRAM_ERR_SCHEMA  -4
#define CEGRAM_ERR_BUFFER_TOO_SMALL -5

static inline uint32_t cegram_le32(uint32_t val) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
           ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF);
#else
    return val;
#endif
}

static inline uint64_t cegram_le64(uint64_t val) {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    return (((uint64_t)cegram_le32((uint32_t)(val & 0xFFFFFFFF))) << 32) |
           cegram_le32((uint32_t)(val >> 32));
#else
    return val;
#endif
}

static inline uint64_t cegram_strtou64(const char *str, int base) {
    uint64_t res = 0;
    if (!str) return 0;
    while (*str == ' ' || *str == '\t') str++;
    if (base == 16 || (base == 0 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))) {
        if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) str += 2;
        while (*str) {
            char c = *str++;
            if (c >= '0' && c <= '9') res = (res << 4) | (c - '0');
            else if (c >= 'a' && c <= 'f') res = (res << 4) | (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') res = (res << 4) | (c - 'A' + 10);
            else break;
        }
    } else {
        while (*str >= '0' && *str <= '9') {
            res = res * 10 + (*str++ - '0');
        }
    }
    return res;
}

#endif
