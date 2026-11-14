#include "cegram/crypto.h"
#include <time.h>

#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
    #include <windows.h>
    #include <wincrypt.h>
#endif

int cegram_random_bytes(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return CEGRAM_ERR_GENERIC;

#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        BOOL res = CryptGenRandom(hProv, (DWORD)len, buf);
        CryptReleaseContext(hProv, 0);
        if (res) return CEGRAM_OK;
    }
#endif

    /* Fallback: pseudo-random (only if OS crypto provider fails) */
    {
        size_t i;
        static int seeded = 0;
        if (!seeded) {
            srand((unsigned int)time(NULL));
            seeded = 1;
        }
        for (i = 0; i < len; ++i) {
            buf[i] = (uint8_t)(rand() & 0xFF);
        }
    }
    return CEGRAM_OK;
}

uint64_t cegram_generate_message_id(void) {
    static uint32_t counter = 0;
    uint64_t sec = (uint64_t)time(NULL);
    counter += 4;
    /* msg_id % 4 must be 0 for client messages */
    return (sec << 32) | ((uint64_t)(counter & 0xFFFFFFFC));
}
