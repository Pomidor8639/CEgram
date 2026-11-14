#include <stdio.h>
#include "cegram/common.h"
#include "cegram/transport.h"
#include "cegram/crypto.h"
#include "cegram/mtproto.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

int main(void) {
    cegram_transport_t transport;
    cegram_respq_t respq;
    uint8_t nonce[16];
    const char *dc_ip = "149.154.167.50"; /* Telegram DC2 */
    uint16_t dc_port = 443;
    int res;
    size_t i;

    printf("=========================================\n");
    printf("   CEgram - Native MTProto 2.0 Test CLI  \n");
    printf("   Targeting Windows CE / Win32 / POSIX  \n");
    printf("=========================================\n\n");

    if (cegram_transport_init() != CEGRAM_OK) {
        printf("[!] Failed to initialize networking subsystem.\n");
        return 1;
    }

    if (cegram_random_bytes(nonce, sizeof(nonce)) != CEGRAM_OK) {
        printf("[!] Failed to generate cryptographically secure random nonce.\n");
        cegram_transport_cleanup();
        return 1;
    }

    print_hex("[*] Client Nonce", nonce, sizeof(nonce));

    printf("[*] Connecting to Telegram DC2 (%s:%u) via raw TCP (Abridged)...\n", dc_ip, dc_port);
    res = cegram_transport_connect(&transport, dc_ip, dc_port);
    if (res != CEGRAM_OK) {
        printf("[!] Failed to connect to Telegram DC2 (error: %d).\n", res);
        cegram_transport_cleanup();
        return 1;
    }
    printf("[+] Connected successfully!\n");

    printf("[*] Sending req_pq_multi unencrypted MTProto packet...\n");
    res = cegram_mtproto_send_req_pq_multi(&transport, nonce, &respq);
    if (res != CEGRAM_OK) {
        printf("[!] Failed to complete req_pq_multi handshake (error: %d).\n", res);
        cegram_transport_disconnect(&transport);
        cegram_transport_cleanup();
        return 1;
    }

    printf("\n[+++] SUCCESS! Received resPQ from Telegram Data Center!\n");
    print_hex("    Server Nonce", respq.server_nonce, sizeof(respq.server_nonce));
    print_hex("    PQ Value", respq.pq, respq.pq_len);
    printf("    RSA Fingerprints count: %u\n", (unsigned int)respq.fingerprint_count);
    for (i = 0; i < respq.fingerprint_count; ++i) {
        printf("      Fingerprint [%u]: 0x%016llX\n", (unsigned int)i, (unsigned long long)respq.fingerprints[i]);
    }

    printf("\n[*] Disconnecting from DC...\n");
    cegram_transport_disconnect(&transport);
    cegram_transport_cleanup();

    printf("[*] Done. MTProto 2.0 core is functioning directly without bridges!\n");
    return 0;
}
