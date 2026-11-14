#ifndef CEGRAM_MTPROTO_H
#define CEGRAM_MTPROTO_H

#include "common.h"
#include "transport.h"
#include "crypto.h"
#include "tl.h"

#define TG_CONSTRUCTOR_REQ_PQ_MULTI         0xbe7e8ef1
#define TG_CONSTRUCTOR_RESPQ                0x05162463
#define TG_CONSTRUCTOR_VECTOR               0x1cb5c415
#define TG_CONSTRUCTOR_REQ_DH_PARAMS        0xd712e4be
#define TG_CONSTRUCTOR_P_Q_INNER_DATA_DC    0xa9f55f95
#define TG_CONSTRUCTOR_SERVER_DH_PARAMS_OK  0xd0e8075c
#define TG_CONSTRUCTOR_SERVER_DH_INNER_DATA 0xb5890dba
#define TG_CONSTRUCTOR_CLIENT_DH_INNER_DATA 0x6643b654
#define TG_CONSTRUCTOR_SET_CLIENT_DH_PARAMS 0xf5045f1f
#define TG_CONSTRUCTOR_DH_GEN_OK            0x3bcbf734
#define TG_CONSTRUCTOR_DH_GEN_RETRY         0x46dc1fb9
#define TG_CONSTRUCTOR_DH_GEN_FAIL          0xa69dae02

#define TG_CONSTRUCTOR_BAD_SERVER_SALT      0xedab447b
#define TG_CONSTRUCTOR_BAD_MSG_NOTIFICATION 0xa7eff811
#define TG_CONSTRUCTOR_RPC_RESULT           0xf35c6d01
#define TG_CONSTRUCTOR_RPC_ERROR            0x2144ca19
#define TG_CONSTRUCTOR_MSG_CONTAINER        0x73f1f8dc
#define TG_CONSTRUCTOR_NEW_SESSION_CREATED  0x9ec20908
#define TG_CONSTRUCTOR_GZIP_PACKED          0x3072c41e

#define TG_CONSTRUCTOR_INVOKE_WITH_LAYER    0xda9b0d0d
#define TG_CONSTRUCTOR_INIT_CONNECTION      0xc1cd5ea9

#define TG_CONSTRUCTOR_HELP_GET_NEAREST_DC  0x1fb33026
#define TG_CONSTRUCTOR_NEAREST_DC           0x8e1a1775

#define TG_CONSTRUCTOR_AUTH_SEND_CODE       0xa677244f
#define TG_CONSTRUCTOR_AUTH_SENT_CODE       0x5e002502
#define TG_CONSTRUCTOR_AUTH_SIGN_IN         0x8d52a951
#define TG_CONSTRUCTOR_AUTH_AUTHORIZATION   0x2ea2c0d4
#define TG_CONSTRUCTOR_AUTH_AUTHORIZATION_OLD 0xcd0509a6
#define TG_CONSTRUCTOR_AUTH_SIGN_UP_REQ     0x10500a36
#define TG_CONSTRUCTOR_CODE_SETTINGS        0xad253d78

#define TG_CONSTRUCTOR_USER                 0xb1b8cc83
#define TG_CONSTRUCTOR_USER_OLD             0xd23c81a3
#define TG_CONSTRUCTOR_CHAT                 0x41cbf256
#define TG_CONSTRUCTOR_CHANNEL              0x7ad15240
#define TG_CONSTRUCTOR_CHAT_FORBIDDEN       0x6592a1a7
#define TG_CONSTRUCTOR_CHANNEL_FORBIDDEN    0x17d493d5

#define TG_CONSTRUCTOR_INPUT_PEER_EMPTY     0x7f3b18ea
#define TG_CONSTRUCTOR_INPUT_PEER_SELF      0x7da07ec9
#define TG_CONSTRUCTOR_INPUT_PEER_CHAT      0x35a95cb9
#define TG_CONSTRUCTOR_INPUT_PEER_USER      0xdde8a54c
#define TG_CONSTRUCTOR_INPUT_PEER_CHANNEL   0x27bcbbfc

#define TG_CONSTRUCTOR_PEER_USER            0x59511722
#define TG_CONSTRUCTOR_PEER_CHAT            0x36c6019a
#define TG_CONSTRUCTOR_PEER_CHANNEL         0xa2a5371e

#define TG_CONSTRUCTOR_PEER_USER_OLD        0x59511761
#define TG_CONSTRUCTOR_PEER_CHAT_OLD        0x36c6088a
#define TG_CONSTRUCTOR_PEER_CHANNEL_OLD     0xa284d356

#define TG_CONSTRUCTOR_MESSAGES_GET_DIALOGS 0xa0f4cb4f
#define TG_CONSTRUCTOR_MESSAGES_DIALOGS     0x15ba6c40
#define TG_CONSTRUCTOR_MESSAGES_DIALOGS_SL  0x71e094f3
#define TG_CONSTRUCTOR_MESSAGES_GET_HISTORY 0x4423e6c5
#define TG_CONSTRUCTOR_MESSAGES_MESSAGES    0x1d73e7ea
#define TG_CONSTRUCTOR_MESSAGES_MESSAGES_SL 0x5f206716
#define TG_CONSTRUCTOR_MESSAGES_SEND_MSG    0xfef48f62

#define TG_CONSTRUCTOR_MESSAGE              0x7600b9d3
#define TG_CONSTRUCTOR_MESSAGE_EMPTY        0x90a6ca84
#define TG_CONSTRUCTOR_DIALOG               0xfc89f7f3

#define CEGRAM_PEER_EMPTY   0
#define CEGRAM_PEER_SELF    1
#define CEGRAM_PEER_USER    2
#define CEGRAM_PEER_CHAT    3
#define CEGRAM_PEER_CHANNEL 4

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    uint8_t pq[16];
    size_t pq_len;
    uint64_t fingerprints[8];
    size_t fingerprint_count;
} cegram_respq_t;

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    uint8_t encrypted_answer[1024];
    size_t encrypted_answer_len;
} cegram_server_dh_params_ok_t;

typedef struct {
    uint8_t nonce[16];
    uint8_t server_nonce[16];
    int32_t g;
    uint8_t dh_prime[512];
    size_t dh_prime_len;
    uint8_t g_a[512];
    size_t g_a_len;
    int32_t server_time;
} cegram_server_dh_inner_data_t;

typedef struct {
    uint8_t auth_key[256];
    uint64_t auth_key_id;
    int32_t time_offset;
    uint64_t server_salt;
    uint64_t session_id;
    int32_t seq_no;
} cegram_session_t;

typedef struct {
    int32_t error_code;
    char error_message[256];
} cegram_rpc_error_t;

typedef struct {
    char phone_code_hash[128];
    int32_t timeout;
    int is_app_code;
} cegram_auth_sent_code_t;

typedef struct {
    uint64_t user_id;
    char first_name[128];
    char last_name[128];
    char username[128];
    char phone[32];
} cegram_user_t;

typedef struct {
    uint64_t peer_id;
    int peer_type;
    uint64_t access_hash;
    char title[128];
    char last_message[256];
    int32_t date;
    int32_t unread_count;
} cegram_dialog_item_t;

typedef struct {
    int32_t id;
    uint64_t from_id;
    int32_t date;
    char message[1024];
    int is_outgoing;
} cegram_message_item_t;

typedef struct {
    int id;
    const char *ip;
    uint16_t port;
} cegram_dc_info_t;

const cegram_dc_info_t *cegram_get_dc_info(int dc_id);

int cegram_mtproto_wrap_init_connection(uint8_t *buf, size_t max_buf_len, size_t *out_len,
                                        int32_t layer, int32_t api_id,
                                        const char *device_model,
                                        const char *system_version,
                                        const char *app_version,
                                        const char *lang_code,
                                        const uint8_t *inner_query, size_t inner_query_len);

int cegram_session_save(const cegram_session_t *session, const char *filepath);
int cegram_session_load(cegram_session_t *session, const char *filepath);

int cegram_mtproto_send_req_pq_multi(cegram_transport_t *t, const uint8_t nonce[16], cegram_respq_t *out_respq);

int cegram_mtproto_send_req_dh_params(cegram_transport_t *t,
                                      const uint8_t nonce[16],
                                      const uint8_t server_nonce[16],
                                      const uint8_t new_nonce[32],
                                      uint32_t p, uint32_t q,
                                      const uint8_t *pq_raw, size_t pq_len,
                                      const cegram_rsa_key_t *key,
                                      int dc_id,
                                      cegram_server_dh_params_ok_t *out_dh);

int cegram_mtproto_decrypt_server_dh_inner(const cegram_server_dh_params_ok_t *server_dh,
                                           const uint8_t new_nonce[32],
                                           cegram_server_dh_inner_data_t *out_inner);

int cegram_mtproto_complete_dh(cegram_transport_t *t,
                              const uint8_t nonce[16],
                              const uint8_t server_nonce[16],
                              const uint8_t new_nonce[32],
                              const cegram_server_dh_inner_data_t *server_dh_inner,
                              cegram_session_t *out_session);

int cegram_mtproto_send_encrypted_ex(cegram_transport_t *t,
                                     cegram_session_t *session,
                                     const uint8_t *payload,
                                     size_t payload_len,
                                     uint64_t *out_msg_id);

int cegram_mtproto_send_encrypted(cegram_transport_t *t,
                                  cegram_session_t *session,
                                  const uint8_t *payload,
                                  size_t payload_len);

int cegram_mtproto_recv_encrypted(cegram_transport_t *t,
                                  cegram_session_t *session,
                                  uint8_t *out_payload,
                                  size_t max_payload_len,
                                  size_t *out_payload_len);

int cegram_mtproto_invoke(cegram_transport_t *t,
                          cegram_session_t *session,
                          const uint8_t *req_payload,
                          size_t req_len,
                          uint8_t *out_resp,
                          size_t max_resp_len,
                          size_t *out_resp_len);

int cegram_auth_send_code(cegram_transport_t *t,
                          cegram_session_t *session,
                          const char *phone_number,
                          int32_t api_id,
                          const char *api_hash,
                          cegram_auth_sent_code_t *out_sent_code,
                          cegram_rpc_error_t *out_error);

int cegram_auth_sign_in(cegram_transport_t *t,
                        cegram_session_t *session,
                        const char *phone_number,
                        const char *phone_code_hash,
                        const char *phone_code,
                        cegram_user_t *out_user,
                        cegram_rpc_error_t *out_error);

int cegram_messages_get_dialogs(cegram_transport_t *t,
                                cegram_session_t *session,
                                int32_t limit,
                                cegram_dialog_item_t *out_dialogs,
                                size_t max_dialogs,
                                size_t *out_count,
                                cegram_rpc_error_t *out_error);

int cegram_messages_get_history(cegram_transport_t *t,
                                cegram_session_t *session,
                                int peer_type,
                                uint64_t peer_id,
                                uint64_t access_hash,
                                int32_t limit,
                                cegram_message_item_t *out_messages,
                                size_t max_messages,
                                size_t *out_count,
                                cegram_rpc_error_t *out_error);

int cegram_messages_send_message(cegram_transport_t *t,
                                 cegram_session_t *session,
                                 int peer_type,
                                 uint64_t peer_id,
                                 uint64_t access_hash,
                                 const char *text,
                                 cegram_rpc_error_t *out_error);

#endif
