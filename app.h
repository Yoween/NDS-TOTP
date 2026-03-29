/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef NDS_TOTP_APP_H
#define NDS_TOTP_APP_H

#include <nds.h>
#include <stdint.h>
#include <stddef.h>

/*
 * Core shared constants and runtime state for the DS application.
 *
 * Notes:
 * - `app_state_t` only stores unlocked material in RAM during runtime.
 * - Time display uses `time_correction_seconds`, derived from user settings.
 */

#define MAX_TOKENS 32
#define MAX_LABEL_LEN 63
#define MAX_KEY_LEN 64
#define LINE_BUF_LEN 256

#define TOKEN_BIN_MAGIC "NTB1"
#define TOKEN_BIN_VERSION_V1 1
#define TOKEN_BIN_VERSION_V2 2
#define TOKEN_BIN_VERSION TOKEN_BIN_VERSION_V2
#define TOKEN_SALT_LEN 16
#define TOKEN_PIN_SALT_LEN 16
#define TOKEN_NONCE_LEN 8
#define TOKEN_TAG_LEN 16
#define PATTERN_MIN_POINTS 5
#define PATTERN_MAX_POINTS 9
#define PIN_MIN_LEN 4
#define PIN_MAX_LEN 8
#define PIN_INPUT_LEN PIN_MAX_LEN
#define KDF_ROUNDS 2048

/* Touch pattern calibration */
#define TOUCH_CELL_W_DIV 3
#define TOUCH_CELL_H_DIV 4
#define TOUCH_HIT_W_PERCENT 32
#define TOUCH_HIT_H_PERCENT 32

/* Bottom screen list layout tuning */
#define UI_TOP_INFO_ROWS 2
#define UI_LIST_TOP_PADDING_ROWS 2
#define UI_CODE_ROW 22
#define UI_GAP_BEFORE_CODE_ROWS 2
#define UI_LABEL_COLS 30
#define UI_SERVICE_GAP_ROWS 1
#define CONSOLE_COLS 32

/* Unlock pattern grid layout (console rows/cols) */
#define UNLOCK_GRID_TOP_ROW 6
#define UNLOCK_GRID_LEFT_COL 4
#define UNLOCK_GRID_ROW_STEP 6
#define UNLOCK_GRID_COL_STEP 10

#define QR_FRAME_W 256
#define QR_FRAME_H 192

typedef struct token_s {
  char label[MAX_LABEL_LEN + 1];
  uint8_t key[MAX_KEY_LEN];
  size_t key_len;
  uint32_t interval;
  int64_t t0;
} token_t;

typedef struct app_state_s {
  PrintConsole top_console;
  PrintConsole bottom_console;
  int tz_offset_minutes;
  int dst_enabled;
  int time_correction_seconds;
  uint8_t enc_key[20];
  uint8_t mac_key[20];
  int has_unlocked_keys;
  char status_msg[96];
} app_state_t;

#endif
