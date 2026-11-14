#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cegram/common.h"
#include "cegram/transport.h"
#include "cegram/crypto.h"
#include "cegram/mtproto.h"
#include "cegram/rsa_keys.h"
#include "cegram/tl.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
    size_t i;
    printf("%s: ", label);
    for (i = 0; i < len; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static int perform_handshake(cegram_transport_t *t, cegram_session_t *session) {
    cegram_respq_t respq;
    cegram_server_dh_params_ok_t server_dh;
    cegram_server_dh_inner_data_t server_dh_inner;
    uint8_t nonce[16];
    uint8_t new_nonce[32];
    uint64_t pq_val = 0;
    uint32_t p = 0, q = 0;
    const cegram_rsa_key_t *matched_key = NULL;
    size_t i;
    int res;

    if (cegram_random_bytes(nonce, sizeof(nonce)) != CEGRAM_OK ||
        cegram_random_bytes(new_nonce, sizeof(new_nonce)) != CEGRAM_OK) {
        printf("[!] Failed to generate cryptographically secure random nonces.\n");
        return CEGRAM_ERR_CRYPTO;
    }

    print_hex("[*] Client Nonce", nonce, sizeof(nonce));

    printf("[*] Sending req_pq_multi unencrypted MTProto packet...\n");
    res = cegram_mtproto_send_req_pq_multi(t, nonce, &respq);
    if (res != CEGRAM_OK) {
        printf("[!] Failed to complete req_pq_multi handshake (error: %d).\n", res);
        return res;
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
        return CEGRAM_ERR_CRYPTO;
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
        return CEGRAM_ERR_CRYPTO;
    }

    print_hex("[*] Generated Client New Nonce", new_nonce, sizeof(new_nonce));
    printf("[*] Encrypting p_q_inner_data_dc with RSA-2048 and sending req_DH_params...\n");
    res = cegram_mtproto_send_req_dh_params(t,
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
        return res;
    }

    printf("\n[+] SUCCESS: Received server_DH_params_ok (%u bytes)!\n", (unsigned int)server_dh.encrypted_answer_len);

    printf("[*] Decrypting server DH answer with AES-256-IGE...\n");
    res = cegram_mtproto_decrypt_server_dh_inner(&server_dh, new_nonce, &server_dh_inner);
    if (res != CEGRAM_OK) {
        printf("[!] Failed to decrypt server_DH_inner_data (error: %d).\n", res);
        return res;
    }

    printf("[+] DH parameters decrypted successfully!\n");
    printf("    Generator g = %d\n", server_dh_inner.g);
    printf("    DH Prime len = %u bytes\n", (unsigned int)server_dh_inner.dh_prime_len);
    printf("    Server g_a len = %u bytes\n", (unsigned int)server_dh_inner.g_a_len);
    printf("    Server Time = %d\n", server_dh_inner.server_time);

    printf("[*] Computing client secret b, g_b, and AuthKey via mini-gmp...\n");
    printf("[*] Sending set_client_DH_params to Telegram DC2...\n");
    res = cegram_mtproto_complete_dh(t,
                                     nonce,
                                     respq.server_nonce,
                                     new_nonce,
                                     &server_dh_inner,
                                     session);
    if (res != CEGRAM_OK) {
        printf("[!] Failed to complete DH exchange (error: %d).\n", res);
        return res;
    }

    printf("\n[+++] MASTER MILESTONE REACHED! Received dh_gen_ok and verified new_nonce_hash1!\n");
    printf("    Auth Key ID: 0x%016llX\n", (unsigned long long)session->auth_key_id);
    print_hex("    Master AuthKey", session->auth_key, 32);
    printf("    (and 224 more bytes of AuthKey)\n");
    printf("    Server Time Offset: %d seconds\n", session->time_offset);

    res = cegram_session_save(session, "session.dat");
    if (res == CEGRAM_OK) {
        printf("[+] Saved persistent session to session.dat\n");
    }

    return CEGRAM_OK;
}

int main(int argc, char **argv) {
    cegram_transport_t transport;
    cegram_session_t session;
    const char *dc_ip = "149.154.167.50";
    uint16_t dc_port = 443;
    int res;
    uint32_t req_get_nearest_dc;
    uint8_t resp_payload[2048];
    size_t resp_payload_len = 0;
    uint32_t resp_constructor;
    char country[32];
    int32_t this_dc = 0;
    int32_t nearest_dc = 0;
    size_t off;

    printf("=========================================\n");
    printf("   CEgram - Native MTProto 2.0 Test CLI  \n");
    printf("   Targeting Windows CE / Win32 / POSIX  \n");
    printf("=========================================\n\n");

    if (cegram_transport_init() != CEGRAM_OK) {
        printf("[!] Failed to initialize networking subsystem.\n");
        return 1;
    }

    memset(&session, 0, sizeof(session));

    printf("[*] Connecting to Telegram DC2 (%s:%u) via raw TCP (Abridged)...\n", dc_ip, dc_port);
    res = cegram_transport_connect(&transport, dc_ip, dc_port);
    if (res != CEGRAM_OK) {
        printf("[!] Failed to connect to Telegram DC2 (error: %d).\n", res);
        cegram_transport_cleanup();
        return 1;
    }
    printf("[+] Connected successfully!\n\n");

    if (cegram_session_load(&session, "session.dat") == CEGRAM_OK) {
        printf("[+] Loaded existing persistent session from session.dat\n");
        printf("    Auth Key ID: 0x%016llX\n", (unsigned long long)session.auth_key_id);
        print_hex("    AuthKey", session.auth_key, 32);
        printf("    Server Salt: 0x%016llX\n\n", (unsigned long long)session.server_salt);
        cegram_random_bytes((uint8_t *)&session.session_id, 8);
        session.seq_no = 0;
    } else {
        printf("[*] No existing session found. Initiating full MTProto 2.0 DH Handshake...\n");
        res = perform_handshake(&transport, &session);
        if (res != CEGRAM_OK) {
            cegram_transport_disconnect(&transport);
            cegram_transport_cleanup();
            return 1;
        }
    }

    printf("=========================================\n");
    printf("   INVOKING MTPROTO 2.0 ENCRYPTED RPC    \n");
    printf("   Method: initConnection(help.getNearestDc) \n");
    printf("=========================================\n\n");

    req_get_nearest_dc = TG_CONSTRUCTOR_HELP_GET_NEAREST_DC;
    uint8_t init_req[512];
    size_t init_req_len = 0;

    cegram_mtproto_wrap_init_connection(init_req, sizeof(init_req), &init_req_len,
                                        184, 2040, "CEgram WinCE", "Windows CE 6.0", "1.0.0", "en",
                                        (const uint8_t *)&req_get_nearest_dc, 4);

    print_hex("[*] init_req bytes", init_req, init_req_len);
    printf("[*] Invoking initConnection + help.getNearestDc via cegram_mtproto_invoke...\n");

    res = cegram_mtproto_invoke(&transport, &session,
                                init_req, init_req_len,
                                resp_payload, sizeof(resp_payload), &resp_payload_len);
    if (res != CEGRAM_OK) {
        printf("[!] RPC invocation failed (error: %d).\n", res);
        cegram_transport_disconnect(&transport);
        cegram_transport_cleanup();
        return 1;
    }

    printf("[+++] SUCCESS: Decrypted and received RPC response payload (%u bytes)!\n", (unsigned int)resp_payload_len);
    print_hex("    Decrypted RPC response", resp_payload, (resp_payload_len > 32) ? 32 : resp_payload_len);

    if (resp_payload_len >= 4) {
        memcpy(&resp_constructor, resp_payload, 4);
        printf("    Response Constructor: 0x%08X\n", resp_constructor);

        if (resp_constructor == TG_CONSTRUCTOR_NEAREST_DC) {
            off = 4;
            if (cegram_tl_read_string(resp_payload, resp_payload_len, &off, country, sizeof(country)) == CEGRAM_OK) {
                cegram_tl_read_uint32(resp_payload, resp_payload_len, &off, (uint32_t *)&this_dc);
                cegram_tl_read_uint32(resp_payload, resp_payload_len, &off, (uint32_t *)&nearest_dc);
                printf("\n[***] TELEGRAM API RESPONSE PARSED SUCCESSFULLY!\n");
                printf("      Detected Country: %s\n", country);
                printf("      Connected DC:     DC%d\n", this_dc);
                printf("      Nearest DC:       DC%d\n\n", nearest_dc);
            }
        } else if (resp_constructor == TG_CONSTRUCTOR_RPC_ERROR) {
            cegram_rpc_error_t err;
            off = 4;
            cegram_tl_read_uint32(resp_payload, resp_payload_len, &off, (uint32_t *)&err.error_code);
            cegram_tl_read_string(resp_payload, resp_payload_len, &off, err.error_message, sizeof(err.error_message));
            printf("[!] Telegram RPC Error %d: %s\n", err.error_code, err.error_message);
        }
    }

    cegram_session_save(&session, "session.dat");

    if (argc >= 4 && (strcmp(argv[1], "sendcode") == 0 || strcmp(argv[1], "login") == 0)) {
        const char *phone = argv[2];
        int32_t api_id = (int32_t)atoi(argv[3]);
        const char *api_hash = (argc >= 5) ? argv[4] : "";
        cegram_auth_sent_code_t sent_code;
        cegram_rpc_error_t err;
        int is_login = (strcmp(argv[1], "login") == 0);
        memset(&err, 0, sizeof(err));
        memset(&sent_code, 0, sizeof(sent_code));

        printf("=========================================\n");
        printf("   TESTING USER AUTH: auth.sendCode      \n");
        printf("=========================================\n\n");
        printf("[*] Phone Number: %s\n", phone);
        printf("[*] API ID:       %d\n", api_id);
        printf("[*] API Hash:     %s\n", api_hash);

        res = cegram_auth_send_code(&transport, &session, phone, api_id, api_hash, &sent_code, &err);
        if (res == CEGRAM_OK) {
            printf("\n[+++] AUTH.SENDCODE SUCCESS!\n");
            printf("      Phone Code Hash: %s\n", sent_code.phone_code_hash);
            printf("      Delivery Type:   %s\n", sent_code.is_app_code ? "Telegram App" : "SMS");
            printf("      Timeout:         %d seconds\n\n", sent_code.timeout);

            if (is_login) {
                char code_buf[32];
                cegram_user_t user;
                memset(&user, 0, sizeof(user));
                memset(code_buf, 0, sizeof(code_buf));

                printf("Enter verification code: ");
                if (fgets(code_buf, sizeof(code_buf), stdin)) {
                    size_t clen = strlen(code_buf);
                    while (clen > 0 && (code_buf[clen - 1] == '\r' || code_buf[clen - 1] == '\n')) {
                        code_buf[--clen] = '\0';
                    }

                    printf("[*] Submitting verification code via auth.signIn...\n");
                    res = cegram_auth_sign_in(&transport, &session, phone, sent_code.phone_code_hash, code_buf, &user, &err);
                    if (res == CEGRAM_OK) {
                        printf("\n[+++] MASTER MILESTONE: AUTHENTICATION SUCCESSFUL!\n");
                        printf("      User ID:   %llu\n", (unsigned long long)user.user_id);
                        printf("      First:     %s\n", user.first_name);
                        printf("      Last:      %s\n", user.last_name);
                        printf("      Username:  @%s\n", user.username);
                        printf("      Phone:     +%s\n\n", user.phone);
                    } else {
                        printf("\n[!] auth.signIn failed (error: %d)\n", res);
                        if (err.error_code != 0) {
                            printf("    Telegram Error %d: %s\n\n", err.error_code, err.error_message);
                        }
                    }
                }
            }
        } else {
            printf("\n[!] auth.sendCode failed (error: %d)\n", res);
            if (err.error_code != 0) {
                printf("    Telegram Error %d: %s\n", err.error_code, err.error_message);
            }
        }
    } else {
        printf("[*] User Authorization Usage:\n");
        printf("    cegram_cli.exe sendcode <phone_number> <api_id> <api_hash>\n");
        printf("    cegram_cli.exe login <phone_number> <api_id> <api_hash>\n");
        printf("    Example: bin\\cegram_cli.exe login +1234567890 2040 b18441a1ff607e10a989891a5462e627\n\n");
    }

    printf("[*] Disconnecting from DC...\n");
    cegram_transport_disconnect(&transport);
    cegram_transport_cleanup();

    printf("[*] CEgram MTProto 2.0 full stack test finished successfully!\n");
    return 0;
}
