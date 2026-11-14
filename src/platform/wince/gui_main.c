#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <commctrl.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cegram/common.h"
#include "cegram/transport.h"
#include "cegram/crypto.h"
#include "cegram/mtproto.h"
#include "cegram/rsa_keys.h"

#define IDC_LOGIN_PHONE       101
#define IDC_LOGIN_API_ID      102
#define IDC_LOGIN_API_HASH    103
#define IDC_LOGIN_SEND_CODE   104
#define IDC_LOGIN_CODE        105
#define IDC_LOGIN_SIGN_IN     106
#define IDC_STATUS_LABEL      107

#define IDC_CHAT_LIST         201
#define IDC_CHAT_HISTORY      202
#define IDC_CHAT_INPUT        203
#define IDC_CHAT_SEND_BTN     204
#define IDC_CHAT_REFRESH_BTN  205
#define IDC_CHAT_LOGOUT_BTN   206

static HINSTANCE g_hInstance = NULL;
static HWND g_hMainWnd = NULL;
static cegram_transport_t g_transport;
static cegram_session_t g_session;
static int g_network_connected = 0;
static int g_logged_in = 0;
static char g_phone_code_hash[128];
static char g_saved_phone[64];

static cegram_dialog_item_t g_dialogs[64];
static size_t g_dialog_count = 0;
static int g_current_dialog_index = -1;

static HWND g_hPhoneLabel = NULL;
static HWND g_hPhoneEdit = NULL;
static HWND g_hApiIdLabel = NULL;
static HWND g_hApiIdEdit = NULL;
static HWND g_hApiHashLabel = NULL;
static HWND g_hApiHashEdit = NULL;
static HWND g_hSendCodeBtn = NULL;
static HWND g_hCodeLabel = NULL;
static HWND g_hCodeEdit = NULL;
static HWND g_hSignInBtn = NULL;
static HWND g_hStatusLabel = NULL;

static HWND g_hChatList = NULL;
static HWND g_hChatHistory = NULL;
static HWND g_hChatInput = NULL;
static HWND g_hChatSendBtn = NULL;
static HWND g_hChatRefreshBtn = NULL;
static HWND g_hChatLogoutBtn = NULL;

static void char_to_tchar(const char *src, TCHAR *dst, size_t max_len) {
#ifdef UNICODE
    MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)max_len);
#else
    strncpy(dst, src, max_len);
    dst[max_len - 1] = '\0';
#endif
}

static void tchar_to_char(const TCHAR *src, char *dst, size_t max_len) {
#ifdef UNICODE
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)max_len, NULL, NULL);
#else
    strncpy(dst, src, max_len);
    dst[max_len - 1] = '\0';
#endif
}

static int cegram_ttoi(const TCHAR *s) {
    int val = 0;
    if (!s) return 0;
    while (*s == TEXT(' ') || *s == TEXT('\t')) s++;
    while (*s >= TEXT('0') && *s <= TEXT('9')) {
        val = val * 10 + (*s - TEXT('0'));
        s++;
    }
    return val;
}

static void set_status(const TCHAR *text) {
    if (g_hStatusLabel) {
        SetWindowText(g_hStatusLabel, text);
    }
}

static int init_network_and_handshake(int dc_id) {
    const cegram_dc_info_t *dc = cegram_get_dc_info(dc_id);
    int res;
    uint8_t nonce[16];
    uint8_t new_nonce[32];
    cegram_respq_t respq;
    cegram_server_dh_params_ok_t server_dh;
    cegram_server_dh_inner_data_t server_dh_inner;
    uint64_t pq_val = 0;
    uint32_t p = 0, q = 0;
    const cegram_rsa_key_t *matched_key = NULL;
    size_t i;
    char sess_file[64];

    if (!dc) return CEGRAM_ERR_GENERIC;

    if (g_network_connected) {
        cegram_transport_disconnect(&g_transport);
        g_network_connected = 0;
    }

    res = cegram_transport_connect(&g_transport, dc->ip, dc->port);
    if (res != CEGRAM_OK) {
        return res;
    }
    g_network_connected = 1;

    snprintf(sess_file, sizeof(sess_file), "session_dc%d.dat", dc_id);
    if (cegram_session_load(&g_session, sess_file) == CEGRAM_OK ||
        (dc_id == 2 && cegram_session_load(&g_session, "session.dat") == CEGRAM_OK)) {
        cegram_random_bytes((uint8_t *)&g_session.session_id, 8);
        g_session.seq_no = 0;
        return CEGRAM_OK;
    }

    cegram_random_bytes(nonce, sizeof(nonce));
    cegram_random_bytes(new_nonce, sizeof(new_nonce));

    res = cegram_mtproto_send_req_pq_multi(&g_transport, nonce, &respq);
    if (res != CEGRAM_OK) return res;

    for (i = 0; i < respq.pq_len; ++i) {
        pq_val = (pq_val << 8) | respq.pq[i];
    }

    if (cegram_factorize_pq(pq_val, &p, &q) != CEGRAM_OK) return CEGRAM_ERR_CRYPTO;

    for (i = 0; i < respq.fingerprint_count; ++i) {
        matched_key = cegram_find_rsa_key(respq.fingerprints[i]);
        if (matched_key) break;
    }
    if (!matched_key) return CEGRAM_ERR_CRYPTO;

    res = cegram_mtproto_send_req_dh_params(&g_transport, nonce, respq.server_nonce, new_nonce,
                                            p, q, respq.pq, respq.pq_len, matched_key, dc_id, &server_dh);
    if (res != CEGRAM_OK) return res;

    res = cegram_mtproto_decrypt_server_dh_inner(&server_dh, new_nonce, &server_dh_inner);
    if (res != CEGRAM_OK) return res;

    res = cegram_mtproto_complete_dh(&g_transport, nonce, respq.server_nonce, new_nonce, &server_dh_inner, &g_session);
    if (res != CEGRAM_OK) return res;

    cegram_session_save(&g_session, sess_file);
    if (dc_id == 2) cegram_session_save(&g_session, "session.dat");

    return CEGRAM_OK;
}

static void show_login_view(int show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    ShowWindow(g_hPhoneLabel, cmd);
    ShowWindow(g_hPhoneEdit, cmd);
    ShowWindow(g_hApiIdLabel, cmd);
    ShowWindow(g_hApiIdEdit, cmd);
    ShowWindow(g_hApiHashLabel, cmd);
    ShowWindow(g_hApiHashEdit, cmd);
    ShowWindow(g_hSendCodeBtn, cmd);
    ShowWindow(g_hCodeLabel, cmd);
    ShowWindow(g_hCodeEdit, cmd);
    ShowWindow(g_hSignInBtn, cmd);
    ShowWindow(g_hStatusLabel, SW_SHOW);
}

static void show_chat_view(int show) {
    int cmd = show ? SW_SHOW : SW_HIDE;
    ShowWindow(g_hChatList, cmd);
    ShowWindow(g_hChatHistory, cmd);
    ShowWindow(g_hChatInput, cmd);
    ShowWindow(g_hChatSendBtn, cmd);
    ShowWindow(g_hChatRefreshBtn, cmd);
    ShowWindow(g_hChatLogoutBtn, cmd);
}

static void layout_controls(HWND hwnd) {
    RECT rc;
    int w, h;
    int margin = 8;
    int input_h = 24;
    int btn_w = 70;
    int left_w;

    GetClientRect(hwnd, &rc);
    w = rc.right - rc.left;
    h = rc.bottom - rc.top;

    if (!g_logged_in) {
        int y = margin;
        int field_w = w - margin * 2;
        if (field_w > 320) field_w = 320;

        MoveWindow(g_hPhoneLabel, margin, y, field_w, 18, TRUE); y += 20;
        MoveWindow(g_hPhoneEdit, margin, y, field_w, input_h, TRUE); y += input_h + 6;

        MoveWindow(g_hApiIdLabel, margin, y, field_w, 18, TRUE); y += 20;
        MoveWindow(g_hApiIdEdit, margin, y, field_w, input_h, TRUE); y += input_h + 6;

        MoveWindow(g_hApiHashLabel, margin, y, field_w, 18, TRUE); y += 20;
        MoveWindow(g_hApiHashEdit, margin, y, field_w, input_h, TRUE); y += input_h + 8;

        MoveWindow(g_hSendCodeBtn, margin, y, 120, 28, TRUE); y += 34;

        MoveWindow(g_hCodeLabel, margin, y, field_w, 18, TRUE); y += 20;
        MoveWindow(g_hCodeEdit, margin, y, field_w, input_h, TRUE); y += input_h + 8;

        MoveWindow(g_hSignInBtn, margin, y, 120, 28, TRUE); y += 36;

        MoveWindow(g_hStatusLabel, margin, y, field_w, 36, TRUE);
    } else {
        left_w = w / 3;
        if (left_w < 110) left_w = 110;
        if (left_w > 260) left_w = 260;

        MoveWindow(g_hChatList, margin, margin, left_w, h - margin * 2 - 32, TRUE);
        MoveWindow(g_hChatRefreshBtn, margin, h - margin - 26, left_w / 2 - 2, 26, TRUE);
        MoveWindow(g_hChatLogoutBtn, margin + left_w / 2 + 2, h - margin - 26, left_w / 2 - 2, 26, TRUE);

        int right_x = margin + left_w + margin;
        int right_w = w - right_x - margin;
        int history_h = h - margin * 2 - input_h - margin;

        MoveWindow(g_hChatHistory, right_x, margin, right_w, history_h, TRUE);
        MoveWindow(g_hChatInput, right_x, margin + history_h + margin, right_w - btn_w - margin, input_h, TRUE);
        MoveWindow(g_hChatSendBtn, right_x + right_w - btn_w, margin + history_h + margin, btn_w, input_h, TRUE);
    }
}

static void load_dialogs(void) {
    cegram_rpc_error_t err;
    size_t count = 0;
    size_t i;
    int res;

    memset(&err, 0, sizeof(err));
    SendMessage(g_hChatList, LB_RESETCONTENT, 0, 0);

    res = cegram_messages_get_dialogs(&g_transport, &g_session, 30, g_dialogs, 64, &count, &err);
    if (res == CEGRAM_OK) {
        g_dialog_count = count;
        for (i = 0; i < count; i++) {
            TCHAR item_text[160];
            TCHAR title_w[128];
            char_to_tchar(g_dialogs[i].title, title_w, sizeof(title_w) / sizeof(TCHAR));
            if (g_dialogs[i].unread_count > 0) {
                _sntprintf(item_text, sizeof(item_text) / sizeof(TCHAR), TEXT("%s (%d)"), title_w, g_dialogs[i].unread_count);
            } else {
                _sntprintf(item_text, sizeof(item_text) / sizeof(TCHAR), TEXT("%s"), title_w);
            }
            SendMessage(g_hChatList, LB_ADDSTRING, 0, (LPARAM)item_text);
        }
        if (count > 0) {
            SendMessage(g_hChatList, LB_SETCURSEL, 0, 0);
            SendMessage(g_hMainWnd, WM_COMMAND, MAKEWPARAM(IDC_CHAT_LIST, LBN_SELCHANGE), (LPARAM)g_hChatList);
        }
    } else {
        TCHAR err_buf[128];
        _sntprintf(err_buf, sizeof(err_buf) / sizeof(TCHAR), TEXT("Failed to load dialogs (%d)"), res);
        set_status(err_buf);
    }
}

static void load_history(int dialog_idx) {
    cegram_message_item_t messages[50];
    size_t count = 0;
    cegram_rpc_error_t err;
    int res;
    size_t i;
    TCHAR total_text[4096];
    size_t text_off = 0;

    if (dialog_idx < 0 || (size_t)dialog_idx >= g_dialog_count) return;

    memset(&err, 0, sizeof(err));
    total_text[0] = TEXT('\0');

    res = cegram_messages_get_history(&g_transport, &g_session,
                                      g_dialogs[dialog_idx].peer_type,
                                      g_dialogs[dialog_idx].peer_id,
                                      g_dialogs[dialog_idx].access_hash,
                                      30, messages, 50, &count, &err);
    if (res == CEGRAM_OK) {
        for (i = count; i > 0; i--) {
            size_t idx = i - 1;
            TCHAR msg_w[1024];
            TCHAR line_buf[1200];
            size_t llen;
            char_to_tchar(messages[idx].message, msg_w, sizeof(msg_w) / sizeof(TCHAR));
            _sntprintf(line_buf, sizeof(line_buf) / sizeof(TCHAR), TEXT("[%s]: %s\r\n"),
                       messages[idx].is_outgoing ? TEXT("Me") : TEXT("Peer"), msg_w);
            llen = _tcslen(line_buf);
            if (text_off + llen < sizeof(total_text) / sizeof(TCHAR) - 1) {
                _tcscpy(total_text + text_off, line_buf);
                text_off += llen;
            }
        }
        SetWindowText(g_hChatHistory, total_text);
        SendMessage(g_hChatHistory, EM_SETSEL, (WPARAM)text_off, (LPARAM)text_off);
        SendMessage(g_hChatHistory, EM_SCROLLCARET, 0, 0);
    } else {
        SetWindowText(g_hChatHistory, TEXT("Failed to fetch messages."));
    }
}

static void send_chat_message(void) {
    TCHAR text_w[1024];
    char text_utf8[1024];
    cegram_rpc_error_t err;
    int res;

    if (g_current_dialog_index < 0 || (size_t)g_current_dialog_index >= g_dialog_count) return;

    GetWindowText(g_hChatInput, text_w, sizeof(text_w) / sizeof(TCHAR));
    if (_tcslen(text_w) == 0) return;

    tchar_to_char(text_w, text_utf8, sizeof(text_utf8));
    memset(&err, 0, sizeof(err));

    res = cegram_messages_send_message(&g_transport, &g_session,
                                       g_dialogs[g_current_dialog_index].peer_type,
                                       g_dialogs[g_current_dialog_index].peer_id,
                                       g_dialogs[g_current_dialog_index].access_hash,
                                       text_utf8, &err);
    if (res == CEGRAM_OK) {
        SetWindowText(g_hChatInput, TEXT(""));
        load_history(g_current_dialog_index);
    } else {
        TCHAR err_buf[128];
        _sntprintf(err_buf, sizeof(err_buf) / sizeof(TCHAR), TEXT("Send failed (%d): %hs"), res, err.error_message);
        set_status(err_buf);
    }
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_hMainWnd = hwnd;

            g_hPhoneLabel = CreateWindow(TEXT("STATIC"), TEXT("Phone Number (+...):"),
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, NULL, g_hInstance, NULL);
            g_hPhoneEdit = CreateWindow(TEXT("EDIT"), TEXT(""),
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_LOGIN_PHONE, g_hInstance, NULL);

            g_hApiIdLabel = CreateWindow(TEXT("STATIC"), TEXT("API ID:"),
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, NULL, g_hInstance, NULL);
            g_hApiIdEdit = CreateWindow(TEXT("EDIT"), TEXT("2040"),
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_LOGIN_API_ID, g_hInstance, NULL);

            g_hApiHashLabel = CreateWindow(TEXT("STATIC"), TEXT("API Hash:"),
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, NULL, g_hInstance, NULL);
            g_hApiHashEdit = CreateWindow(TEXT("EDIT"), TEXT("b18441a1ff607e10a989891a5462e627"),
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_LOGIN_API_HASH, g_hInstance, NULL);

            g_hSendCodeBtn = CreateWindow(TEXT("BUTTON"), TEXT("Send Code"),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)IDC_LOGIN_SEND_CODE, g_hInstance, NULL);

            g_hCodeLabel = CreateWindow(TEXT("STATIC"), TEXT("SMS / Telegram Code:"),
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, NULL, g_hInstance, NULL);
            g_hCodeEdit = CreateWindow(TEXT("EDIT"), TEXT(""),
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_LOGIN_CODE, g_hInstance, NULL);

            g_hSignInBtn = CreateWindow(TEXT("BUTTON"), TEXT("Sign In"),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)IDC_LOGIN_SIGN_IN, g_hInstance, NULL);

            g_hStatusLabel = CreateWindow(TEXT("STATIC"), TEXT("Connecting to Telegram MTProto 2.0..."),
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS_LABEL, g_hInstance, NULL);

            g_hChatList = CreateWindow(TEXT("LISTBOX"), TEXT(""),
                WS_CHILD | WS_BORDER | LBS_NOTIFY | WS_VSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHAT_LIST, g_hInstance, NULL);

            g_hChatHistory = CreateWindow(TEXT("EDIT"), TEXT(""),
                WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                0, 0, 0, 0, hwnd, (HMENU)IDC_CHAT_HISTORY, g_hInstance, NULL);

            g_hChatInput = CreateWindow(TEXT("EDIT"), TEXT(""),
                WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHAT_INPUT, g_hInstance, NULL);

            g_hChatSendBtn = CreateWindow(TEXT("BUTTON"), TEXT("Send"),
                WS_CHILD | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHAT_SEND_BTN, g_hInstance, NULL);

            g_hChatRefreshBtn = CreateWindow(TEXT("BUTTON"), TEXT("Refresh"),
                WS_CHILD | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHAT_REFRESH_BTN, g_hInstance, NULL);

            g_hChatLogoutBtn = CreateWindow(TEXT("BUTTON"), TEXT("Logout"),
                WS_CHILD | BS_PUSHBUTTON, 0, 0, 0, 0, hwnd, (HMENU)IDC_CHAT_LOGOUT_BTN, g_hInstance, NULL);

            show_login_view(1);
            show_chat_view(0);
            layout_controls(hwnd);

            if (init_network_and_handshake(2) == CEGRAM_OK) {
                cegram_dialog_item_t test_dialogs[2];
                size_t test_count = 0;
                cegram_rpc_error_t test_err;
                memset(&test_err, 0, sizeof(test_err));

                if (cegram_messages_get_dialogs(&g_transport, &g_session, 1, test_dialogs, 2, &test_count, &test_err) == CEGRAM_OK) {
                    g_logged_in = 1;
                    show_login_view(0);
                    show_chat_view(1);
                    layout_controls(hwnd);
                    load_dialogs();
                    set_status(TEXT("Online"));
                } else {
                    set_status(TEXT("Connected to DC2. Please log in."));
                }
            } else {
                set_status(TEXT("Network connection error!"));
            }
            break;
        }

        case WM_SIZE: {
            layout_controls(hwnd);
            break;
        }

        case WM_COMMAND: {
            int wmId = LOWORD(wParam);
            int wmEvent = HIWORD(wParam);

            if (wmId == IDC_LOGIN_SEND_CODE) {
                TCHAR phone_w[64], api_id_w[32], api_hash_w[64];
                char phone_utf8[64], api_hash_utf8[64];
                int32_t api_id;
                cegram_auth_sent_code_t sent_code;
                cegram_rpc_error_t err;
                int res;

                GetWindowText(g_hPhoneEdit, phone_w, sizeof(phone_w) / sizeof(TCHAR));
                GetWindowText(g_hApiIdEdit, api_id_w, sizeof(api_id_w) / sizeof(TCHAR));
                GetWindowText(g_hApiHashEdit, api_hash_w, sizeof(api_hash_w) / sizeof(TCHAR));

                tchar_to_char(phone_w, phone_utf8, sizeof(phone_utf8));
                tchar_to_char(api_hash_w, api_hash_utf8, sizeof(api_hash_utf8));
                api_id = (int32_t)cegram_ttoi(api_id_w);

                strncpy(g_saved_phone, phone_utf8, sizeof(g_saved_phone));
                set_status(TEXT("Sending verification code..."));
                memset(&err, 0, sizeof(err));
                memset(&sent_code, 0, sizeof(sent_code));

                res = cegram_auth_send_code(&g_transport, &g_session, phone_utf8, api_id, api_hash_utf8, &sent_code, &err);
                if (res != CEGRAM_OK && err.error_code == 303 && strncmp(err.error_message, "PHONE_MIGRATE_", 14) == 0) {
                    int target_dc = atoi(err.error_message + 14);
                    set_status(TEXT("Migrating to another DC..."));
                    if (init_network_and_handshake(target_dc) == CEGRAM_OK) {
                        memset(&err, 0, sizeof(err));
                        memset(&sent_code, 0, sizeof(sent_code));
                        res = cegram_auth_send_code(&g_transport, &g_session, phone_utf8, api_id, api_hash_utf8, &sent_code, &err);
                    }
                }

                if (res == CEGRAM_OK) {
                    strncpy(g_phone_code_hash, sent_code.phone_code_hash, sizeof(g_phone_code_hash));
                    set_status(sent_code.is_app_code ? TEXT("Code sent to Telegram app!") : TEXT("Code sent via SMS!"));
                } else {
                    TCHAR err_buf[128];
                    _sntprintf(err_buf, sizeof(err_buf) / sizeof(TCHAR), TEXT("Send code error: %hs"), err.error_message);
                    set_status(err_buf);
                }
            } else if (wmId == IDC_LOGIN_SIGN_IN) {
                TCHAR code_w[32];
                char code_utf8[32];
                cegram_user_t user;
                cegram_rpc_error_t err;
                int res;

                GetWindowText(g_hCodeEdit, code_w, sizeof(code_w) / sizeof(TCHAR));
                tchar_to_char(code_w, code_utf8, sizeof(code_utf8));

                set_status(TEXT("Signing in..."));
                memset(&err, 0, sizeof(err));
                memset(&user, 0, sizeof(user));

                res = cegram_auth_sign_in(&g_transport, &g_session, g_saved_phone, g_phone_code_hash, code_utf8, &user, &err);
                if (res == CEGRAM_OK) {
                    cegram_session_save(&g_session, "session.dat");
                    g_logged_in = 1;
                    show_login_view(0);
                    show_chat_view(1);
                    layout_controls(hwnd);
                    load_dialogs();
                    set_status(TEXT("Logged in!"));
                } else {
                    TCHAR err_buf[128];
                    _sntprintf(err_buf, sizeof(err_buf) / sizeof(TCHAR), TEXT("Sign in error: %hs"), err.error_message);
                    set_status(err_buf);
                }
            } else if (wmId == IDC_CHAT_LIST && wmEvent == LBN_SELCHANGE) {
                int sel = (int)SendMessage(g_hChatList, LB_GETCURSEL, 0, 0);
                if (sel != LB_ERR) {
                    g_current_dialog_index = sel;
                    load_history(sel);
                }
            } else if (wmId == IDC_CHAT_SEND_BTN) {
                send_chat_message();
            } else if (wmId == IDC_CHAT_REFRESH_BTN) {
                load_dialogs();
            } else if (wmId == IDC_CHAT_LOGOUT_BTN) {
                DeleteFile(TEXT("session.dat"));
                g_logged_in = 0;
                show_chat_view(0);
                show_login_view(1);
                layout_controls(hwnd);
                set_status(TEXT("Logged out. Please log in."));
            }
            break;
        }

        case WM_DESTROY: {
            if (g_network_connected) {
                cegram_transport_disconnect(&g_transport);
                g_network_connected = 0;
            }
            cegram_transport_cleanup();
            PostQuitMessage(0);
            break;
        }

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

#if defined(CEGRAM_PLATFORM_WINCE) || defined(UNDER_CE)
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
#endif
    WNDCLASS wc;
    HWND hwnd;
    MSG msg;

    g_hInstance = hInstance;

    if (cegram_transport_init() != CEGRAM_OK) {
        MessageBox(NULL, TEXT("Failed to initialize Winsock!"), TEXT("CEgram Error"), MB_OK | MB_ICONERROR);
        return 1;
    }

    memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = TEXT("CEgramWindowClass");
#ifndef UNDER_CE
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
#endif

    if (!RegisterClass(&wc)) {
        return 1;
    }

    hwnd = CreateWindowEx(
        0,
        TEXT("CEgramWindowClass"),
        TEXT("CEgram - Telegram for Windows CE"),
        WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT,
        480, 400,
        NULL, NULL, hInstance, NULL
    );

    if (!hwnd) return 1;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
