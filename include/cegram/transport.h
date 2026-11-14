#ifndef CEGRAM_TRANSPORT_H
#define CEGRAM_TRANSPORT_H

#include "common.h"

#if defined(CEGRAM_PLATFORM_WINCE) || defined(CEGRAM_PLATFORM_WIN32)
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef SOCKET cegram_socket_t;
    #define CEGRAM_INVALID_SOCKET INVALID_SOCKET
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    typedef int cegram_socket_t;
    #define CEGRAM_INVALID_SOCKET (-1)
#endif

typedef struct {
    cegram_socket_t sock;
    int is_connected;
    int transport_type;
} cegram_transport_t;

int cegram_transport_init(void);
void cegram_transport_cleanup(void);

int cegram_transport_connect(cegram_transport_t *t, const char *ip, uint16_t port);
void cegram_transport_disconnect(cegram_transport_t *t);

int cegram_transport_send(cegram_transport_t *t, const uint8_t *data, size_t len);
int cegram_transport_recv(cegram_transport_t *t, uint8_t *buf, size_t max_len, size_t *out_len);

#endif
