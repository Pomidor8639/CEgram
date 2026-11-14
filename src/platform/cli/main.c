#include <stdio.h>
#include "cegram/common.h"
#include "cegram/transport.h"
#include "cegram/crypto.h"
#include "cegram/mtproto.h"
#include "cegram/rsa_keys.h"

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
    cegram_server_dh_params_ok_t server_dh;
    uint8_t nonce[16];
    uint8_t new_nonce[32];
    uint64_t pq_val = 0;
    uint32_t p = 0, q = 0;
    const cegram_rsa_key_t *matched_key = NULL;
    const char *dc_ip = "149.154.167.50";
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

    if (cegram_random_bytes(nonce, sizeof(nonce)) != CEGRAM_OK ||
        cegram_random_bytes(new_nonce, sizeof(new_nonce)) != CEGRAM_OK) {
        printf("[!] Failed to generate cryptographically secure random nonces.\n");
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

    printf("\n[+] SUCCESS: Received resPQ from Telegram DC!\n");
    print_hex("    Server Nonce", respq.server_nonce, sizeof(respq.server_nonce));
    print_hex("    PQ Bytes", respq.pq, respq.pq_len);

    for (i = 0; i < respq.pq_len; ++i) {
        pq_val = (pq_val << 8) | respq.pq[i];
    }
    printf("    PQ Value: %llu (0x%llX)\n", (unsigned long long)pq_val, (unsigned long long)pq_val);

    printf("[*] Factorizing PQ using Pollard's rho algorithm...\n");
    if (cegram_factorize_pq(pq_val, &p, &q) != CEGRAM_OK) {
        printf("[!] Failed to factorize PQ!\n");
        cegram_transport_disconnect(&transport);
        cegram_transport_cleanup();
        return 1;
    }
    printf("[+] Factored successfully: P = %u (0x%08X), Q = %u (0x%08X)\n", p, p, q, q);

    printf("[*] Matching Telegram Server RSA Fingerprints...\n");
    for (i = 0; i < respq.fingerprint_count; ++i) {
        matched_key = cegram_find_rsa_key(respq.fingerprints[i]);
        if (matched_key) {
            printf("[+] Matched RSA key with fingerprint: 0x%016llX\n", (unsigned long long)matched_key->fingerprint);
            break;
        }
    }

    if (!matched_key) {
        printf("[!] None of the server's %u RSA fingerprints matched our embedded keys!\n",
               (unsigned int)respq.fingerprint_count);
        cegram_transport_disconnect(&transport);
        cegram_transport_cleanup();
        return 1;
    }

    print_hex("[*] Generated Client New Nonce", new_nonce, sizeof(new_nonce));
    printf("[*] Encrypting p_q_inner_data_dc with RSA-2048 and sending req_DH_params...\n");
    res = cegram_mtproto_send_req_dh_params(&transport,
                                           nonce,
                                           respq.server_nonce,
                                           new_nonce,
                                           p, q,
                                           respq.pq, respq.pq_len,
                                           matched_key,
                                           2,
                                           &server_dh);
    if (res != CEGRAM_OK) {
        printf("[!] Failed to complete req_DH_params (error: %d).\n", res);
        cegram_transport_disconnect(&transport);
        cegram_transport_cleanup();
        return 1;
    }

    printf("\n[+++] FANTASTIC SUCCESS! Received server_DH_params_ok!\n");
    print_hex("    Verified Nonce", server_dh.nonce, 16);
    print_hex("    Server Nonce", server_dh.server_nonce, 16);
    printf("    Encrypted DH Answer size: %u bytes\n", (unsigned int)server_dh.encrypted_answer_len);

    printf("\n[*] Disconnecting from DC...\n");
    cegram_transport_disconnect(&transport);
    cegram_transport_cleanup();

    printf("[*] MTProto 2.0 Auth Key Creation Step 2 (req_DH_params) is COMPLETE!\n");
    return 0;
}
