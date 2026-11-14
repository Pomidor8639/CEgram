#include "cegram/transport.h"

int cegram_transport_init(void) {
#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return CEGRAM_ERR_NETWORK;
    }
#endif
    return CEGRAM_OK;
}

void cegram_transport_cleanup(void) {
#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
    WSACleanup();
#endif
}

int cegram_transport_connect(cegram_transport_t *t, const char *ip, uint16_t port) {
    struct sockaddr_in server_addr;
    uint8_t handshake_byte = 0xef;

    if (!t) return CEGRAM_ERR_GENERIC;

    t->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (t->sock == CEGRAM_INVALID_SOCKET) {
        return CEGRAM_ERR_NETWORK;
    }

#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
    DWORD timeout = 10000;
    setsockopt(t->sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(t->sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(t->sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(t->sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
#endif

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(t->sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
        closesocket(t->sock);
#else
        close(t->sock);
#endif
        t->sock = CEGRAM_INVALID_SOCKET;
        return CEGRAM_ERR_NETWORK;
    }

    if (send(t->sock, (const char *)&handshake_byte, 1, 0) != 1) {
        cegram_transport_disconnect(t);
        return CEGRAM_ERR_NETWORK;
    }

    t->is_connected = 1;
    t->transport_type = 0;
    return CEGRAM_OK;
}

void cegram_transport_disconnect(cegram_transport_t *t) {
    if (!t) return;
    if (t->sock != CEGRAM_INVALID_SOCKET) {
#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
        closesocket(t->sock);
#else
        close(t->sock);
#endif
        t->sock = CEGRAM_INVALID_SOCKET;
    }
    t->is_connected = 0;
}

int cegram_transport_send(cegram_transport_t *t, const uint8_t *data, size_t len) {
    uint8_t header[4];
    size_t header_len = 0;
    size_t words = len / 4;
    int sent;

    if (!t || !t->is_connected || (len % 4 != 0)) {
        return CEGRAM_ERR_GENERIC;
    }

    if (words < 127) {
        header[0] = (uint8_t)words;
        header_len = 1;
    } else {
        header[0] = 0x7f;
        header[1] = (uint8_t)(words & 0xff);
        header[2] = (uint8_t)((words >> 8) & 0xff);
        header[3] = (uint8_t)((words >> 16) & 0xff);
        header_len = 4;
    }

    sent = send(t->sock, (const char *)header, (int)header_len, 0);
    if (sent != (int)header_len) {
        return CEGRAM_ERR_NETWORK;
    }

    sent = send(t->sock, (const char *)data, (int)len, 0);
    if (sent != (int)len) {
        return CEGRAM_ERR_NETWORK;
    }

    return CEGRAM_OK;
}

static int recv_all(cegram_socket_t sock, uint8_t *buf, size_t len) {
    size_t received = 0;
    while (received < len) {
        int r = recv(sock, (char *)buf + received, (int)(len - received), 0);
        if (r <= 0) return CEGRAM_ERR_NETWORK;
        received += (size_t)r;
    }
    return CEGRAM_OK;
}

int cegram_transport_recv(cegram_transport_t *t, uint8_t *buf, size_t max_len, size_t *out_len) {
    uint8_t first_byte;
    size_t words = 0;
    size_t payload_len;

    if (!t || !t->is_connected || !buf || !out_len) {
        return CEGRAM_ERR_GENERIC;
    }

    if (recv_all(t->sock, &first_byte, 1) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    if (first_byte < 0x7f) {
        words = first_byte;
    } else if (first_byte == 0x7f) {
        uint8_t len_bytes[3];
        if (recv_all(t->sock, len_bytes, 3) != CEGRAM_OK) {
            return CEGRAM_ERR_NETWORK;
        }
        words = (size_t)len_bytes[0] | ((size_t)len_bytes[1] << 8) | ((size_t)len_bytes[2] << 16);
    } else {
        return CEGRAM_ERR_NETWORK;
    }

    payload_len = words * 4;
    if (payload_len > max_len) {
        return CEGRAM_ERR_GENERIC;
    }

    if (recv_all(t->sock, buf, payload_len) != CEGRAM_OK) {
        return CEGRAM_ERR_NETWORK;
    }

    *out_len = payload_len;
    return CEGRAM_OK;
}
