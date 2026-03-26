/*
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2019-2025, Michael Santos <michael.santos@gmail.com>
 *  Copyright (c) 2015, David M. Syzdek <david@syzdek.net>
 *  All rights reserved.
 */

#include <fat.h>
#include <hmac/hmac.h>
#include <nds.h>
#include <quirc.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <calico/nds/pxi.h>
#include "camera.h"

#define MAX_TOKENS 32
#define MAX_LABEL_LEN 63
#define MAX_KEY_LEN 64
#define LINE_BUF_LEN 256
#define TOKEN_BIN_MAGIC "NTB1"
#define TOKEN_BIN_VERSION 1
#define TOKEN_SALT_LEN 16
#define TOKEN_NONCE_LEN 8
#define TOKEN_TAG_LEN 16
#define PATTERN_MIN_POINTS 4
#define PATTERN_MAX_POINTS 9
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

#define QR_DETECT_ONLY 0

/*
 * Manual correction applied to time(NULL) before TOTP computation.
 * Example: if the DS runs +3600s ahead, set to -3600.
 */
#define TIME_CORRECTION_SECONDS -3600

static int g_time_correction_seconds = TIME_CORRECTION_SECONDS;

static PrintConsole g_top_console;
static PrintConsole g_bottom_console;
static uint8_t g_enc_key[20];
static uint8_t g_mac_key[20];
static int g_has_unlocked_keys = 0;
static char g_status_msg[96];
static struct quirc_code g_qr_code;
static struct quirc_data g_qr_data;

#define QR_FRAME_W 256
#define QR_FRAME_H 192

static const int8_t base32_vals[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    14, 11, 26, 27, 28, 29, 30, 31, 1,  -1, -1, -1, -1, 0,  -1, -1,
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

typedef struct token_s {
  char label[MAX_LABEL_LEN + 1];
  uint8_t key[MAX_KEY_LEN];
  size_t key_len;
  uint32_t interval;
  int64_t t0;
} token_t;



static int parse_time_correction_line(const char *line, int *value) {
  const char *eq;
  long parsed;

  eq = strchr(line, '=');
  if (eq == NULL)
    return 0;

  if ((strncmp(line, "time_correction", (size_t)(eq - line)) != 0) &&
      (strncmp(line, "TIME_CORRECTION_SECONDS", (size_t)(eq - line)) != 0))
    return 0;

  parsed = strtol(eq + 1, NULL, 0);
  if (parsed < -86400)
    parsed = -86400;
  if (parsed > 86400)
    parsed = 86400;
  *value = (int)parsed;
  return 1;
}



static char *trim(char *s) {
  char *end;

  while ((*s == ' ') || (*s == '\t') || (*s == '\r') || (*s == '\n'))
    s++;

  if (*s == '\0')
    return s;

  end = s + strlen(s) - 1;
  while ((end > s) && ((*end == ' ') || (*end == '\t') || (*end == '\r') ||
                       (*end == '\n')))
    end--;
  end[1] = '\0';

  return s;
}

static int base32_decode(const char *in, uint8_t *out, size_t out_cap,
                         size_t *out_len) {
  size_t len;
  size_t pos;
  size_t keylen;

  len = strlen(in);
  if (len == 0)
    return -1;

  if (((len & 0xF) != 0) && ((len & 0xF) != 8))
    return -1;

  for (pos = 0; pos < len; pos++) {
    uint8_t ch = (uint8_t)in[pos];

    if (base32_vals[ch] == -1)
      return -1;

    if (ch == '=') {
      if (((pos & 0xF) == 0) || ((pos & 0xF) == 8))
        return -1;
      if ((len - pos) > 6)
        return -1;

      switch (pos % 8) {
      case 2:
      case 4:
      case 5:
      case 7:
        break;
      default:
        return -1;
      }

      for (; pos < len; pos++) {
        if (in[pos] != '=')
          return -1;
      }
      break;
    }
  }

  keylen = 0;
  for (pos = 0; pos <= (len - 8); pos += 8) {
    if ((keylen + 5) > out_cap)
      return -1;

    out[keylen + 0] = (base32_vals[(uint8_t)in[pos + 0]] << 3) & 0xF8;
    out[keylen + 0] |= (base32_vals[(uint8_t)in[pos + 1]] >> 2) & 0x07;
    if (in[pos + 2] == '=') {
      keylen += 1;
      break;
    }

    out[keylen + 1] = (base32_vals[(uint8_t)in[pos + 1]] << 6) & 0xC0;
    out[keylen + 1] |= (base32_vals[(uint8_t)in[pos + 2]] << 1) & 0x3E;
    out[keylen + 1] |= (base32_vals[(uint8_t)in[pos + 3]] >> 4) & 0x01;
    if (in[pos + 4] == '=') {
      keylen += 2;
      break;
    }

    out[keylen + 2] = (base32_vals[(uint8_t)in[pos + 3]] << 4) & 0xF0;
    out[keylen + 2] |= (base32_vals[(uint8_t)in[pos + 4]] >> 1) & 0x0F;
    if (in[pos + 5] == '=') {
      keylen += 3;
      break;
    }

    out[keylen + 3] = (base32_vals[(uint8_t)in[pos + 4]] << 7) & 0x80;
    out[keylen + 3] |= (base32_vals[(uint8_t)in[pos + 5]] << 2) & 0x7C;
    out[keylen + 3] |= (base32_vals[(uint8_t)in[pos + 6]] >> 3) & 0x03;
    if (in[pos + 7] == '=') {
      keylen += 4;
      break;
    }

    out[keylen + 4] = (base32_vals[(uint8_t)in[pos + 6]] << 5) & 0xE0;
    out[keylen + 4] |= (base32_vals[(uint8_t)in[pos + 7]] >> 0) & 0x1F;
    keylen += 5;
  }

  *out_len = keylen;
  return 0;
}

static uint32_t compute_totp(const token_t *token, time_t now) {
  uint64_t counter;
  uint8_t msg[8] = {0};
  uint8_t hmac_result[20] = {0};
  size_t hmac_len;
  uint64_t offset;
  uint32_t bin_code;
  int64_t elapsed;

  if (token->interval == 0)
    return 0;

  elapsed = (int64_t)now - token->t0;
  if (elapsed < 0)
    return 0;

  counter = (uint64_t)(elapsed / (int64_t)token->interval);

  msg[0] = (uint8_t)((counter >> 56) & 0xFF);
  msg[1] = (uint8_t)((counter >> 48) & 0xFF);
  msg[2] = (uint8_t)((counter >> 40) & 0xFF);
  msg[3] = (uint8_t)((counter >> 32) & 0xFF);
  msg[4] = (uint8_t)((counter >> 24) & 0xFF);
  msg[5] = (uint8_t)((counter >> 16) & 0xFF);
  msg[6] = (uint8_t)((counter >> 8) & 0xFF);
  msg[7] = (uint8_t)(counter & 0xFF);

  hmac_len = sizeof(hmac_result);
  hmac_sha1(token->key, token->key_len, msg, sizeof(msg), hmac_result, &hmac_len);

  offset = hmac_result[19] & 0x0F;
  bin_code = (hmac_result[offset] & 0x7F) << 24 |
             (hmac_result[offset + 1] & 0xFF) << 16 |
             (hmac_result[offset + 2] & 0xFF) << 8 |
             (hmac_result[offset + 3] & 0xFF);

  return bin_code % 1000000;
}

static uint16_t read_u16_le(FILE *fp, int *ok) {
  uint8_t b[2];
  if ((fread(b, 1, 2, fp) != 2) || (*ok == 0)) {
    *ok = 0;
    return 0;
  }
  return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static uint32_t read_u32_le(FILE *fp, int *ok) {
  uint8_t b[4];
  if ((fread(b, 1, 4, fp) != 4) || (*ok == 0)) {
    *ok = 0;
    return 0;
  }
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
         ((uint32_t)b[3] << 24);
}

static int64_t read_i64_le(FILE *fp, int *ok) {
  uint8_t b[8];
  uint64_t v;
  if ((fread(b, 1, 8, fp) != 8) || (*ok == 0)) {
    *ok = 0;
    return 0;
  }
  v = (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
      ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
      ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
  return (int64_t)v;
}

static void hmac20(const uint8_t *key, size_t key_len, const uint8_t *msg,
                   size_t msg_len, uint8_t out[20]) {
  size_t out_len = 20;
  hmac_sha1(key, key_len, msg, msg_len, out, &out_len);
}

static void derive_keys_from_pattern(const uint8_t *pattern, size_t pattern_len,
                                     const uint8_t salt[TOKEN_SALT_LEN],
                                     uint8_t enc_key[20],
                                     uint8_t mac_key[20]) {
  uint8_t seed[20];
  uint8_t msg[TOKEN_SALT_LEN + 2];
  uint16_t i;

  if ((pattern_len == 0) || (pattern_len > PATTERN_MAX_POINTS)) {
    memset(enc_key, 0, 20);
    memset(mac_key, 0, 20);
    return;
  }

  memcpy(msg, salt, TOKEN_SALT_LEN);
  msg[TOKEN_SALT_LEN] = (uint8_t)pattern_len;
  msg[TOKEN_SALT_LEN + 1] = 0xA5;
  hmac20(pattern, pattern_len, msg, sizeof(msg), seed);

  for (i = 0; i < KDF_ROUNDS; i++) {
    msg[TOKEN_SALT_LEN] = (uint8_t)(i & 0xFF);
    msg[TOKEN_SALT_LEN + 1] = (uint8_t)(((i >> 8) & 0xFF) ^ 0x5A);
    hmac20(seed, sizeof(seed), msg, sizeof(msg), seed);
  }

  hmac20(seed, sizeof(seed), (const uint8_t *)"enc", 3, enc_key);
  hmac20(seed, sizeof(seed), (const uint8_t *)"mac", 3, mac_key);
}

static void stream_xor(const uint8_t enc_key[20],
                       const uint8_t nonce[TOKEN_NONCE_LEN], uint8_t *buf,
                       size_t len) {
  uint8_t block[20];
  uint8_t msg[TOKEN_NONCE_LEN + 4];
  uint32_t counter = 0;
  size_t pos = 0;
  size_t i;

  while (pos < len) {
    memcpy(msg, nonce, TOKEN_NONCE_LEN);
    msg[TOKEN_NONCE_LEN + 0] = (uint8_t)((counter >> 24) & 0xFF);
    msg[TOKEN_NONCE_LEN + 1] = (uint8_t)((counter >> 16) & 0xFF);
    msg[TOKEN_NONCE_LEN + 2] = (uint8_t)((counter >> 8) & 0xFF);
    msg[TOKEN_NONCE_LEN + 3] = (uint8_t)(counter & 0xFF);
    hmac20(enc_key, 20, msg, sizeof(msg), block);

    for (i = 0; (i < sizeof(block)) && (pos < len); i++, pos++)
      buf[pos] ^= block[i];

    counter++;
  }
}

static void compute_entry_tag(const uint8_t mac_key[20], uint8_t label_len,
                              uint8_t key_len, uint32_t interval, int64_t t0,
                              const uint8_t nonce[TOKEN_NONCE_LEN],
                              const uint8_t *cipher, size_t cipher_len,
                              uint8_t out_tag[20]) {
  uint8_t mac_buf[2 + 4 + 8 + TOKEN_NONCE_LEN + MAX_LABEL_LEN + MAX_KEY_LEN];
  size_t p = 0;
  uint64_t t0u = (uint64_t)t0;

  mac_buf[p++] = label_len;
  mac_buf[p++] = key_len;
  mac_buf[p++] = (uint8_t)(interval & 0xFF);
  mac_buf[p++] = (uint8_t)((interval >> 8) & 0xFF);
  mac_buf[p++] = (uint8_t)((interval >> 16) & 0xFF);
  mac_buf[p++] = (uint8_t)((interval >> 24) & 0xFF);
  mac_buf[p++] = (uint8_t)(t0u & 0xFF);
  mac_buf[p++] = (uint8_t)((t0u >> 8) & 0xFF);
  mac_buf[p++] = (uint8_t)((t0u >> 16) & 0xFF);
  mac_buf[p++] = (uint8_t)((t0u >> 24) & 0xFF);
  mac_buf[p++] = (uint8_t)((t0u >> 32) & 0xFF);
  mac_buf[p++] = (uint8_t)((t0u >> 40) & 0xFF);
  mac_buf[p++] = (uint8_t)((t0u >> 48) & 0xFF);
  mac_buf[p++] = (uint8_t)((t0u >> 56) & 0xFF);
  memcpy(&mac_buf[p], nonce, TOKEN_NONCE_LEN);
  p += TOKEN_NONCE_LEN;
  if (cipher_len > 0) {
    memcpy(&mac_buf[p], cipher, cipher_len);
    p += cipher_len;
  }

  hmac20(mac_key, 20, mac_buf, p, out_tag);
}

static int load_tokens_bin_with_keys(token_t *tokens, size_t *count,
                                     const char **loaded_path,
                                     const uint8_t enc_key[20],
                                     const uint8_t mac_key[20]) {
  static const char *paths[] = {
      "sd:/totp/tokens.bin",
      "fat:/totp/tokens.bin",
      "/totp/tokens.bin",
  };
  FILE *fp = NULL;
  uint8_t magic[4];
  uint8_t version;
  uint8_t salt[TOKEN_SALT_LEN];
  uint16_t entry_count;
  size_t idx;
  int ok = 1;
  uint16_t e;

  *count = 0;
  *loaded_path = NULL;

  for (idx = 0; idx < (sizeof(paths) / sizeof(paths[0])); idx++) {
    fp = fopen(paths[idx], "rb");
    if (fp != NULL) {
      *loaded_path = paths[idx];
      break;
    }
  }

  if (fp == NULL)
    return -1;

  if (fread(magic, 1, 4, fp) != 4)
    ok = 0;
  if ((magic[0] != TOKEN_BIN_MAGIC[0]) || (magic[1] != TOKEN_BIN_MAGIC[1]) ||
      (magic[2] != TOKEN_BIN_MAGIC[2]) || (magic[3] != TOKEN_BIN_MAGIC[3]))
    ok = 0;

  if (fread(&version, 1, 1, fp) != 1)
    ok = 0;
  if (version != TOKEN_BIN_VERSION)
    ok = 0;

  if (fread(salt, 1, TOKEN_SALT_LEN, fp) != TOKEN_SALT_LEN)
    ok = 0;

  entry_count = read_u16_le(fp, &ok);
  if (!ok) {
    fclose(fp);
    return -2;
  }

  for (e = 0; e < entry_count; e++) {
    uint8_t nonce[TOKEN_NONCE_LEN];
    uint8_t label_len;
    uint8_t key_len;
    uint32_t interval;
    int64_t t0;
    uint8_t cipher[MAX_LABEL_LEN + MAX_KEY_LEN];
    uint8_t plain[MAX_LABEL_LEN + MAX_KEY_LEN];
    uint8_t tag[TOKEN_TAG_LEN];
    uint8_t expected_tag[20];
    token_t token;
    size_t payload_len;
    size_t i;

    if (fread(nonce, 1, TOKEN_NONCE_LEN, fp) != TOKEN_NONCE_LEN)
      ok = 0;
    if (fread(&label_len, 1, 1, fp) != 1)
      ok = 0;
    if (fread(&key_len, 1, 1, fp) != 1)
      ok = 0;
    interval = read_u32_le(fp, &ok);
    t0 = read_i64_le(fp, &ok);

    payload_len = (size_t)label_len + (size_t)key_len;
    if ((payload_len == 0) || (label_len > MAX_LABEL_LEN) ||
        (key_len == 0) || (key_len > MAX_KEY_LEN) ||
        (payload_len > sizeof(cipher)) || (interval == 0))
      ok = 0;

    if (ok && (fread(cipher, 1, payload_len, fp) != payload_len))
      ok = 0;
    if (ok && (fread(tag, 1, TOKEN_TAG_LEN, fp) != TOKEN_TAG_LEN))
      ok = 0;
    if (!ok)
      break;

    compute_entry_tag(mac_key, label_len, key_len, interval, t0, nonce, cipher,
                      payload_len, expected_tag);
    for (i = 0; i < TOKEN_TAG_LEN; i++) {
      if (tag[i] != expected_tag[i]) {
        ok = 0;
        break;
      }
    }
    if (!ok)
      break;

    memcpy(plain, cipher, payload_len);
    stream_xor(enc_key, nonce, plain, payload_len);

    memset(&token, 0, sizeof(token));
    memcpy(token.label, plain, label_len);
    token.label[label_len] = '\0';
    memcpy(token.key, plain + label_len, key_len);
    token.key_len = key_len;
    token.interval = interval;
    token.t0 = t0;

    if (*count < MAX_TOKENS) {
      tokens[*count] = token;
      (*count)++;
    }
  }

  fclose(fp);
  return ok ? 0 : -2;
}

static int read_tokens_bin_salt(uint8_t out_salt[TOKEN_SALT_LEN],
                                const char **loaded_path) {
  static const char *paths[] = {
      "sd:/totp/tokens.bin",
      "fat:/totp/tokens.bin",
      "/totp/tokens.bin",
  };
  FILE *fp = NULL;
  uint8_t magic[4];
  uint8_t version;
  size_t idx;

  *loaded_path = NULL;

  for (idx = 0; idx < (sizeof(paths) / sizeof(paths[0])); idx++) {
    fp = fopen(paths[idx], "rb");
    if (fp != NULL) {
      *loaded_path = paths[idx];
      break;
    }
  }

  if (fp == NULL)
    return -1;

  if ((fread(magic, 1, 4, fp) != 4) || (fread(&version, 1, 1, fp) != 1) ||
      (fread(out_salt, 1, TOKEN_SALT_LEN, fp) != TOKEN_SALT_LEN)) {
    fclose(fp);
    return -1;
  }

  fclose(fp);
  if ((magic[0] != TOKEN_BIN_MAGIC[0]) || (magic[1] != TOKEN_BIN_MAGIC[1]) ||
      (magic[2] != TOKEN_BIN_MAGIC[2]) || (magic[3] != TOKEN_BIN_MAGIC[3]) ||
      (version != TOKEN_BIN_VERSION))
    return -1;

  return 0;
}

static int hex_val(char c) {
  if ((c >= '0') && (c <= '9'))
    return c - '0';
  if ((c >= 'A') && (c <= 'F'))
    return 10 + (c - 'A');
  if ((c >= 'a') && (c <= 'f'))
    return 10 + (c - 'a');
  return -1;
}

static int percent_decode(const char *src, char *dst, size_t dst_cap) {
  size_t si = 0;
  size_t di = 0;

  if (dst_cap == 0)
    return -1;

  while (src[si] != '\0') {
    char ch = src[si];
    if (di + 1 >= dst_cap)
      return -1;

    if ((ch == '%') && (src[si + 1] != '\0') && (src[si + 2] != '\0')) {
      int hi = hex_val(src[si + 1]);
      int lo = hex_val(src[si + 2]);
      if ((hi < 0) || (lo < 0))
        return -1;
      dst[di++] = (char)((hi << 4) | lo);
      si += 3;
      continue;
    }

    if (ch == '+')
      ch = ' ';
    dst[di++] = ch;
    si++;
  }

  dst[di] = '\0';
  return 0;
}

static void copy_trunc(char *dst, size_t dst_cap, const char *src) {
  size_t n;
  if (dst_cap == 0)
    return;
  n = strlen(src);
  if (n >= dst_cap)
    n = dst_cap - 1;
  memcpy(dst, src, n);
  dst[n] = '\0';
}

static void join_label(char *dst, size_t dst_cap, const char *issuer,
                       const char *path_label) {
  size_t p = 0;
  size_t n;

  if (dst_cap == 0)
    return;

  if ((issuer != NULL) && (issuer[0] != '\0')) {
    n = strlen(issuer);
    if (n > dst_cap - 1)
      n = dst_cap - 1;
    memcpy(dst + p, issuer, n);
    p += n;
    if (p < dst_cap - 1)
      dst[p++] = ':';
  }

  n = strlen(path_label);
  if (n > (dst_cap - 1 - p))
    n = dst_cap - 1 - p;
  memcpy(dst + p, path_label, n);
  p += n;
  dst[p] = '\0';
}

static void sanitize_base32_secret(char *s) {
  size_t i;
  size_t j = 0;
  for (i = 0; s[i] != '\0'; i++) {
    char c = s[i];
    if ((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n') ||
        (c == '-'))
      continue;
    s[j++] = c;
  }
  s[j] = '\0';
}

static int decode_base32_flexible(const char *secret, uint8_t *out,
                                  size_t out_cap, size_t *out_len) {
  char core[192];
  char padded[200];
  size_t i;
  size_t n = 0;
  size_t rem;
  size_t pad;

  for (i = 0; secret[i] != '\0'; i++) {
    char c = secret[i];

    if ((c == ' ') || (c == '\t') || (c == '\r') || (c == '\n') ||
        (c == '-') || (c == '_') || (c == '='))
      continue;

    if ((c >= 'a') && (c <= 'z'))
      c = (char)(c - 'a' + 'A');

    if (!(((c >= 'A') && (c <= 'Z')) || ((c >= '2') && (c <= '7'))))
      return -1;

    if (n + 1 >= sizeof(core))
      return -1;
    core[n++] = c;
  }

  if (n == 0)
    return -1;

  rem = n % 8;
  if ((rem == 1) || (rem == 3) || (rem == 6))
    return -1;

  pad = (8 - rem) % 8;
  if ((n + pad + 1) > sizeof(padded))
    return -1;

  memcpy(padded, core, n);
  for (i = 0; i < pad; i++)
    padded[n + i] = '=';
  padded[n + pad] = '\0';

  return base32_decode(padded, out, out_cap, out_len);
}

static int parse_otpauth_uri(const char *uri, token_t *out, char *err,
                             size_t err_cap) {
  static const char *prefix = "otpauth://totp/";
  const char *q;
  char path_part[128];
  char path_decoded[128];
  char issuer[64] = "";
  char secret_raw[160] = "";
  char algorithm[16] = "";
  uint32_t interval = 30;
  int digits = 6;
  size_t out_key_len = 0;
  size_t prefix_len = strlen(prefix);

  if (strncmp(uri, prefix, prefix_len) != 0) {
    snprintf(err, err_cap, "URI otpauth://totp attendu");
    return -1;
  }

  q = strchr(uri + prefix_len, '?');
  if (q == NULL) {
    snprintf(err, err_cap, "Query string manquante");
    return -1;
  }

  {
    size_t path_len = (size_t)(q - (uri + prefix_len));
    if ((path_len == 0) || (path_len >= sizeof(path_part))) {
      snprintf(err, err_cap, "Label invalide");
      return -1;
    }
    memcpy(path_part, uri + prefix_len, path_len);
    path_part[path_len] = '\0';
  }

  if (percent_decode(path_part, path_decoded, sizeof(path_decoded)) < 0) {
    snprintf(err, err_cap, "Label encode invalide");
    return -1;
  }

  {
    char query[256];
    char *tok;
    char *saveptr = NULL;
    size_t qlen = strlen(q + 1);
    if (qlen >= sizeof(query)) {
      snprintf(err, err_cap, "Query trop longue");
      return -1;
    }
    memcpy(query, q + 1, qlen + 1);

    tok = strtok_r(query, "&", &saveptr);
    while (tok != NULL) {
      char *eq = strchr(tok, '=');
      if (eq != NULL) {
        char key[32];
        char val[192];
        size_t klen = (size_t)(eq - tok);

        if (klen >= sizeof(key)) {
          tok = strtok_r(NULL, "&", &saveptr);
          continue;
        }

        memcpy(key, tok, klen);
        key[klen] = '\0';
        if (percent_decode(eq + 1, val, sizeof(val)) == 0) {
          if (strcmp(key, "secret") == 0) {
            copy_trunc(secret_raw, sizeof(secret_raw), val);
          } else if (strcmp(key, "issuer") == 0) {
            copy_trunc(issuer, sizeof(issuer), val);
          } else if (strcmp(key, "period") == 0) {
            unsigned long p = strtoul(val, NULL, 10);
            if ((p > 0) && (p <= 3600))
              interval = (uint32_t)p;
          } else if (strcmp(key, "digits") == 0) {
            digits = (int)strtol(val, NULL, 10);
          } else if (strcmp(key, "algorithm") == 0) {
            copy_trunc(algorithm, sizeof(algorithm), val);
          }
        }
      }

      tok = strtok_r(NULL, "&", &saveptr);
    }
  }

  if (secret_raw[0] == '\0') {
    snprintf(err, err_cap, "Param secret manquant");
    return -1;
  }
  sanitize_base32_secret(secret_raw);

  if ((algorithm[0] != '\0') &&
      (strcmp(algorithm, "SHA1") != 0) && (strcmp(algorithm, "sha1") != 0)) {
    snprintf(err, err_cap, "Algo non supporte (SHA1 seulement)");
    return -1;
  }

  if (digits != 6) {
    snprintf(err, err_cap, "Digits non supporte (%d)", digits);
    return -1;
  }

  memset(out, 0, sizeof(*out));
  join_label(out->label, sizeof(out->label), issuer, path_decoded);

  if (decode_base32_flexible(secret_raw, out->key, sizeof(out->key),
                             &out_key_len) < 0) {
    snprintf(err, err_cap, "Secret base32 invalide");
    return -1;
  }

  out->key_len = out_key_len;
  out->interval = interval;
  out->t0 = 0;
  return 0;
}

static void make_entry_nonce(const uint8_t enc_key[20], uint8_t nonce[8]) {
  uint8_t msg[12];
  uint8_t out[20];
  static uint32_t counter = 0;
  uint32_t t = (uint32_t)time(NULL);
  uint32_t mix = t ^ ((uint32_t)REG_VCOUNT << 16) ^ (counter * 0x9E3779B9u);

  msg[0] = (uint8_t)(t & 0xFF);
  msg[1] = (uint8_t)((t >> 8) & 0xFF);
  msg[2] = (uint8_t)((t >> 16) & 0xFF);
  msg[3] = (uint8_t)((t >> 24) & 0xFF);
  msg[4] = (uint8_t)(mix & 0xFF);
  msg[5] = (uint8_t)((mix >> 8) & 0xFF);
  msg[6] = (uint8_t)((mix >> 16) & 0xFF);
  msg[7] = (uint8_t)((mix >> 24) & 0xFF);
  msg[8] = (uint8_t)(counter & 0xFF);
  msg[9] = (uint8_t)((counter >> 8) & 0xFF);
  msg[10] = (uint8_t)((counter >> 16) & 0xFF);
  msg[11] = (uint8_t)((counter >> 24) & 0xFF);
  counter++;

  hmac20(enc_key, 20, msg, sizeof(msg), out);
  memcpy(nonce, out, TOKEN_NONCE_LEN);
}

static int append_token_bin_entry(const char *bin_path, const token_t *token,
                                  const uint8_t enc_key[20],
                                  const uint8_t mac_key[20]) {
  FILE *fp;
  uint8_t magic[4];
  uint8_t version;
  uint8_t salt[TOKEN_SALT_LEN];
  uint8_t c[2];
  uint16_t count;
  uint16_t new_count;
  uint8_t nonce[TOKEN_NONCE_LEN];
  uint8_t lens[2];
  uint8_t interval_le[4];
  uint8_t t0_le[8];
  uint8_t plain[MAX_LABEL_LEN + MAX_KEY_LEN];
  uint8_t cipher[MAX_LABEL_LEN + MAX_KEY_LEN];
  uint8_t tag[20];
  size_t label_len;
  size_t payload_len;
  uint64_t t0u;

  label_len = strlen(token->label);
  if ((label_len == 0) || (label_len > MAX_LABEL_LEN) ||
      (token->key_len == 0) || (token->key_len > MAX_KEY_LEN) ||
      (token->interval == 0))
    return -1;

  fp = fopen(bin_path, "r+b");
  if (fp == NULL)
    return -1;

  if ((fread(magic, 1, 4, fp) != 4) || (fread(&version, 1, 1, fp) != 1) ||
      (fread(salt, 1, TOKEN_SALT_LEN, fp) != TOKEN_SALT_LEN) ||
      (fread(c, 1, 2, fp) != 2)) {
    fclose(fp);
    return -1;
  }

  if ((magic[0] != TOKEN_BIN_MAGIC[0]) || (magic[1] != TOKEN_BIN_MAGIC[1]) ||
      (magic[2] != TOKEN_BIN_MAGIC[2]) || (magic[3] != TOKEN_BIN_MAGIC[3]) ||
      (version != TOKEN_BIN_VERSION)) {
    fclose(fp);
    return -1;
  }

  count = (uint16_t)c[0] | ((uint16_t)c[1] << 8);
  if (count == 65535u) {
    fclose(fp);
    return -1;
  }
  new_count = (uint16_t)(count + 1u);

  make_entry_nonce(enc_key, nonce);
  memcpy(plain, token->label, label_len);
  memcpy(plain + label_len, token->key, token->key_len);
  payload_len = label_len + token->key_len;
  memcpy(cipher, plain, payload_len);
  stream_xor(enc_key, nonce, cipher, payload_len);

  lens[0] = (uint8_t)label_len;
  lens[1] = (uint8_t)token->key_len;
  interval_le[0] = (uint8_t)(token->interval & 0xFF);
  interval_le[1] = (uint8_t)((token->interval >> 8) & 0xFF);
  interval_le[2] = (uint8_t)((token->interval >> 16) & 0xFF);
  interval_le[3] = (uint8_t)((token->interval >> 24) & 0xFF);
  t0u = (uint64_t)token->t0;
  t0_le[0] = (uint8_t)(t0u & 0xFF);
  t0_le[1] = (uint8_t)((t0u >> 8) & 0xFF);
  t0_le[2] = (uint8_t)((t0u >> 16) & 0xFF);
  t0_le[3] = (uint8_t)((t0u >> 24) & 0xFF);
  t0_le[4] = (uint8_t)((t0u >> 32) & 0xFF);
  t0_le[5] = (uint8_t)((t0u >> 40) & 0xFF);
  t0_le[6] = (uint8_t)((t0u >> 48) & 0xFF);
  t0_le[7] = (uint8_t)((t0u >> 56) & 0xFF);

  compute_entry_tag(mac_key, lens[0], lens[1], token->interval, token->t0,
                    nonce, cipher, payload_len, tag);

  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return -1;
  }
  if ((fwrite(nonce, 1, TOKEN_NONCE_LEN, fp) != TOKEN_NONCE_LEN) ||
      (fwrite(lens, 1, 2, fp) != 2) || (fwrite(interval_le, 1, 4, fp) != 4) ||
      (fwrite(t0_le, 1, 8, fp) != 8) ||
      (fwrite(cipher, 1, payload_len, fp) != payload_len) ||
      (fwrite(tag, 1, TOKEN_TAG_LEN, fp) != TOKEN_TAG_LEN)) {
    fclose(fp);
    return -1;
  }

  c[0] = (uint8_t)(new_count & 0xFF);
  c[1] = (uint8_t)((new_count >> 8) & 0xFF);
  if (fseek(fp, 4 + 1 + TOKEN_SALT_LEN, SEEK_SET) != 0) {
    fclose(fp);
    return -1;
  }
  if (fwrite(c, 1, 2, fp) != 2) {
    fclose(fp);
    return -1;
  }

  fclose(fp);
  return 0;
}

static int rewrite_tokens_bin_with_keys(const char *bin_path,
                                        const uint8_t salt[TOKEN_SALT_LEN],
                                        const uint8_t enc_key[20],
                                        const uint8_t mac_key[20],
                                        const token_t *tokens, size_t count) {
  FILE *fp;
  uint8_t count_le[2];
  size_t i;

  if (count > 65535)
    return -1;

  fp = fopen(bin_path, "wb");
  if (fp == NULL)
    return -1;

  count_le[0] = (uint8_t)(count & 0xFF);
  count_le[1] = (uint8_t)((count >> 8) & 0xFF);

  if ((fwrite(TOKEN_BIN_MAGIC, 1, 4, fp) != 4) ||
      (fputc(TOKEN_BIN_VERSION, fp) == EOF) ||
      (fwrite(salt, 1, TOKEN_SALT_LEN, fp) != TOKEN_SALT_LEN) ||
      (fwrite(count_le, 1, 2, fp) != 2)) {
    fclose(fp);
    return -1;
  }

  for (i = 0; i < count; i++) {
    uint8_t nonce[TOKEN_NONCE_LEN];
    uint8_t lens[2];
    uint8_t interval_le[4];
    uint8_t t0_le[8];
    uint8_t plain[MAX_LABEL_LEN + MAX_KEY_LEN];
    uint8_t cipher[MAX_LABEL_LEN + MAX_KEY_LEN];
    uint8_t tag[20];
    size_t label_len = strlen(tokens[i].label);
    size_t payload_len;
    uint64_t t0u;

    if ((label_len == 0) || (label_len > MAX_LABEL_LEN) ||
        (tokens[i].key_len == 0) || (tokens[i].key_len > MAX_KEY_LEN) ||
        (tokens[i].interval == 0)) {
      fclose(fp);
      return -1;
    }

    payload_len = label_len + tokens[i].key_len;
    make_entry_nonce(enc_key, nonce);

    memcpy(plain, tokens[i].label, label_len);
    memcpy(plain + label_len, tokens[i].key, tokens[i].key_len);
    memcpy(cipher, plain, payload_len);
    stream_xor(enc_key, nonce, cipher, payload_len);

    lens[0] = (uint8_t)label_len;
    lens[1] = (uint8_t)tokens[i].key_len;
    interval_le[0] = (uint8_t)(tokens[i].interval & 0xFF);
    interval_le[1] = (uint8_t)((tokens[i].interval >> 8) & 0xFF);
    interval_le[2] = (uint8_t)((tokens[i].interval >> 16) & 0xFF);
    interval_le[3] = (uint8_t)((tokens[i].interval >> 24) & 0xFF);
    t0u = (uint64_t)tokens[i].t0;
    t0_le[0] = (uint8_t)(t0u & 0xFF);
    t0_le[1] = (uint8_t)((t0u >> 8) & 0xFF);
    t0_le[2] = (uint8_t)((t0u >> 16) & 0xFF);
    t0_le[3] = (uint8_t)((t0u >> 24) & 0xFF);
    t0_le[4] = (uint8_t)((t0u >> 32) & 0xFF);
    t0_le[5] = (uint8_t)((t0u >> 40) & 0xFF);
    t0_le[6] = (uint8_t)((t0u >> 48) & 0xFF);
    t0_le[7] = (uint8_t)((t0u >> 56) & 0xFF);

    compute_entry_tag(mac_key, lens[0], lens[1], tokens[i].interval,
                      tokens[i].t0, nonce, cipher, payload_len, tag);

    if ((fwrite(nonce, 1, TOKEN_NONCE_LEN, fp) != TOKEN_NONCE_LEN) ||
        (fwrite(lens, 1, 2, fp) != 2) || (fwrite(interval_le, 1, 4, fp) != 4) ||
        (fwrite(t0_le, 1, 8, fp) != 8) ||
        (fwrite(cipher, 1, payload_len, fp) != payload_len) ||
        (fwrite(tag, 1, TOKEN_TAG_LEN, fp) != TOKEN_TAG_LEN)) {
      fclose(fp);
      return -1;
    }
  }

  fclose(fp);
  return 0;
}

static int touch_to_pattern_cell(int x, int y) {
  const int cell_w = SCREEN_WIDTH / TOUCH_CELL_W_DIV;
  const int cell_h = SCREEN_HEIGHT / TOUCH_CELL_H_DIV;
  const int grid_w = cell_w * 3;
  const int grid_h = cell_h * 3;
  const int left = (SCREEN_WIDTH - grid_w) / 2;
  const int top = (SCREEN_HEIGHT - grid_h) / 2;
  const int hit_w = (cell_w * TOUCH_HIT_W_PERCENT) / 100;
  const int hit_h = (cell_h * TOUCH_HIT_H_PERCENT) / 100;
  int col = 0;
  int row = 0;
  int best_dx;
  int best_dy;
  int i;

  best_dx = abs(x - (left + cell_w / 2));
  for (i = 1; i < 3; i++) {
    int cx = left + i * cell_w + cell_w / 2;
    int dx = abs(x - cx);
    if (dx < best_dx) {
      best_dx = dx;
      col = i;
    }
  }

  best_dy = abs(y - (top + cell_h / 2));
  for (i = 1; i < 3; i++) {
    int cy = top + i * cell_h + cell_h / 2;
    int dy = abs(y - cy);
    if (dy < best_dy) {
      best_dy = dy;
      row = i;
    }
  }

  if ((best_dx > hit_w) || (best_dy > hit_h))
    return -1;

  return row * 3 + col;
}

static void top_at(int row, int col, const char *fmt, ...) {
  char buf[128];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  iprintf("\x1b[%d;%dH%s", row, col, buf);
}

static void bottom_at(int row, int col, const char *fmt, ...) {
  char buf[128];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  printf("\x1b[%d;%dH%s", row, col, buf);
}

static void clear_bottom_row(int row) {
  bottom_at(row, 1, "%*s", CONSOLE_COLS, "");
}

static void clear_top_row(int row) {
  top_at(row, 1, "%*s", CONSOLE_COLS, "");
}

static void restore_text_consoles(void) {
  videoSetMode(MODE_0_2D);
  videoSetModeSub(MODE_0_2D);
  vramSetBankA(VRAM_A_MAIN_BG);
  vramSetBankC(VRAM_C_SUB_BG);
  consoleInit(&g_top_console, 0, BgType_Text4bpp, BgSize_T_256x256, 31, 0, true,
              true);
  consoleInit(&g_bottom_console, 0, BgType_Text4bpp, BgSize_T_256x256, 31, 0,
              false, true);
}

static void rgb555_to_gray8(const uint16_t *src, uint8_t *dst, size_t count) {
  size_t i;
  for (i = 0; i < count; i++) {
    uint16_t px = src[i];
    uint8_t r = (uint8_t)(px & 0x1F);
    uint8_t g = (uint8_t)((px >> 5) & 0x1F);
    uint8_t b = (uint8_t)((px >> 10) & 0x1F);
    uint8_t r8 = (uint8_t)(r << 3);
    uint8_t g8 = (uint8_t)(g << 3);
    uint8_t b8 = (uint8_t)(b << 3);
    dst[i] = (uint8_t)(((uint16_t)r8 * 30 + (uint16_t)g8 * 59 +
                        (uint16_t)b8 * 11) /
                       100);
  }
}

static void camera_transfer_stop_sync(void) {
  int guard;

  cameraTransferStop();
  for (guard = 0; guard < 400 && cameraTransferActive(); guard++)
    swiWaitForVBlank();
}

static int scan_otpauth_qr(char *out_uri, size_t out_cap, char *err,
                           size_t err_cap) {
  struct quirc *qr;
  int bg;
  uint16_t *frame;
  Camera active_cam = CAM_OUTER;
  int frame_idx;
  int stall_frames = 0;
  int recoveries = 0;
  int decode_tick = 0;

  if (out_cap == 0)
    return -1;

  out_uri[0] = '\0';
  err[0] = '\0';

  if (!isDSiMode()) {
    snprintf(err, err_cap, "QR camera: DSi requis");
    return -1;
  }

  qr = quirc_new();
  if (qr == NULL) {
    snprintf(err, err_cap, "QR init memoire echoue");
    return -1;
  }

  if (quirc_resize(qr, QR_FRAME_W, QR_FRAME_H) < 0) {
    quirc_destroy(qr);
    snprintf(err, err_cap, "QR resize echoue");
    return -1;
  }

  videoSetMode(MODE_5_2D);
  vramSetBankA(VRAM_A_MAIN_BG_0x06040000);
  bg = bgInit(2, BgType_Bmp16, BgSize_B16_256x256, 16, 0);
  frame = (uint16_t *)bgGetGfxPtr(bg);
  memset(frame, 0, (size_t)QR_FRAME_W * (size_t)QR_FRAME_H * sizeof(uint16_t));

  pxiWaitRemote(PXI_CAMERA);
  if (!cameraInit() || !cameraActivate(active_cam)) {
    quirc_destroy(qr);
    restore_text_consoles();
    snprintf(err, err_cap, "Camera init/activate failed");
    return -1;
  }

  consoleSelect(&g_bottom_console);
  printf("\x1b[2J");
  bottom_at(1, 1, "Scan QR...");
  bottom_at(2, 1, "B: switch cam");
  bottom_at(3, 1, "START: cancel");
  bottom_at(4, 1, "State: init capture");

  cameraTransferStart(frame, CAPTURE_MODE_PREVIEW);

  for (frame_idx = 0; frame_idx < 1200; frame_idx++) {
    int keys;
    int w;
    int h;
    int n;
  #if !QR_DETECT_ONLY
    int i;
  #endif
    uint8_t *img;

    scanKeys();
    keys = keysDown();
    if (keys & KEY_START) {
      snprintf(err, err_cap, "Scan cancelled");
      camera_transfer_stop_sync();
      cameraDeactivate(active_cam);
      quirc_destroy(qr);
      restore_text_consoles();
      return -2;
    }

    if (keys & KEY_B) {
      Camera next = (active_cam == CAM_OUTER) ? CAM_INNER : CAM_OUTER;
      camera_transfer_stop_sync();
      if (cameraActivate(next))
        active_cam = next;
      cameraTransferStart(frame, CAPTURE_MODE_PREVIEW);
      stall_frames = 0;
      recoveries = 0;
      decode_tick = 0;
      bottom_at(4, 1, "State: switch camera   ");
      continue;
    }

    if (cameraTransferActive()) {
      stall_frames++;
      if ((frame_idx % 20) == 0)
        bottom_at(4, 1, "State: capturing... %4d", frame_idx);

      if (stall_frames > 300) {
        recoveries++;
        bottom_at(4, 1, "State: recovery %d     ", recoveries);
        camera_transfer_stop_sync();
        if (recoveries > 8) {
          cameraDeactivate(active_cam);
          quirc_destroy(qr);
          restore_text_consoles();
          snprintf(err, err_cap, "Camera stalled (no frame)");
          return -1;
        }
        cameraTransferStart(frame, CAPTURE_MODE_PREVIEW);
        stall_frames = 0;
      }
      swiWaitForVBlank();
      continue;
    }

    stall_frames = 0;
    recoveries = 0;
    decode_tick++;
    if ((frame_idx % 20) == 0)
      bottom_at(4, 1, "State: decode...  %4d", frame_idx);

    if ((decode_tick & 1) != 0) {
      img = quirc_begin(qr, &w, &h);
      if ((w == QR_FRAME_W) && (h == QR_FRAME_H)) {
        rgb555_to_gray8(frame, img, (size_t)QR_FRAME_W * (size_t)QR_FRAME_H);
      }
      quirc_end(qr);

      n = quirc_count(qr);
      if (n > 0) {
        clear_bottom_row(5);
        clear_bottom_row(6);
        bottom_at(5, 1, "QR detecte (%d)", n);
        bottom_at(6, 1, "Traitement...");
#if QR_DETECT_ONLY
        camera_transfer_stop_sync();
        cameraDeactivate(active_cam);
        quirc_destroy(qr);
        restore_text_consoles();
        snprintf(err, err_cap, "QR detecte (test)");
        return -3;
#else
        camera_transfer_stop_sync();
        cameraDeactivate(active_cam);

        if (n > 1)
          n = 1;

        for (i = 0; i < n; i++) {
          quirc_decode_error_t dec;
          size_t payload_len;

          quirc_extract(qr, i, &g_qr_code);

          dec = quirc_decode(&g_qr_code, &g_qr_data);
          if (dec != QUIRC_SUCCESS) {
            quirc_flip(&g_qr_code);
            dec = quirc_decode(&g_qr_code, &g_qr_data);
          }
          if (dec != QUIRC_SUCCESS)
            continue;

          payload_len = (size_t)g_qr_data.payload_len;
          if (payload_len >= out_cap)
            payload_len = out_cap - 1;
          memcpy(out_uri, g_qr_data.payload, payload_len);
          out_uri[payload_len] = '\0';

          if (strncmp(out_uri, "otpauth://totp/", 15) == 0) {
            clear_bottom_row(5);
            clear_bottom_row(6);
            bottom_at(5, 1, "QR detected and read");
            bottom_at(6, 1, "otpauth valid, import...");
            quirc_destroy(qr);
            restore_text_consoles();
            return 0;
          }
        }

        quirc_destroy(qr);
        restore_text_consoles();
        snprintf(err, err_cap, "QR detected but non-otpauth\n  Please try scanning again");
        return -1;
#endif
      }
    }

    cameraTransferStart(frame, CAPTURE_MODE_PREVIEW);

    swiWaitForVBlank();
  }

  camera_transfer_stop_sync();
  cameraDeactivate(active_cam);
  quirc_destroy(qr);
  restore_text_consoles();
  snprintf(err, err_cap, "No otpauth QR code found");
  return -1;
}

static void draw_unlock_screen(const uint8_t visited[9], size_t pattern_len,
                               int attempts_left, const char *status) {
  int r;
  int c;
  const int grid_top_row = UNLOCK_GRID_TOP_ROW;
  const int grid_left_col = UNLOCK_GRID_LEFT_COL;
  const int grid_row_step = UNLOCK_GRID_ROW_STEP;
  const int grid_col_step = UNLOCK_GRID_COL_STEP;

  consoleSelect(&g_top_console);
  iprintf("\x1b[2J");
  top_at(1, 1, "NDS-TOTP LOCKED");
  top_at(3, 1, "Draw 3x3 pattern");
  top_at(4, 1, "on touch screen");
  top_at(6, 1, "Tries left: %d", attempts_left);
  clear_top_row(7);
  if ((status != NULL) && (status[0] != '\0'))
    top_at(7, 1, "%s", status);

  consoleSelect(&g_bottom_console);
  printf("\x1b[2J");
  bottom_at(1, 1, "Draw unlock pattern");
  bottom_at(2, 1, "Entered points: %lu", (unsigned long)pattern_len);

  for (r = 0; r < 3; r++) {
    for (c = 0; c < 3; c++) {
      int idx = r * 3 + c;
      int row = grid_top_row + (r * grid_row_step);
      int col = grid_left_col + (c * grid_col_step);
      bottom_at(row, col, "[%c]", visited[idx] ? '*' : ' ');
    }
  }

  bottom_at(23, 1, "START: quit");
}

static int unlock_and_load_tokens(token_t *tokens, size_t *count,
                                  const char **loaded_path) {
  uint8_t salt[TOKEN_SALT_LEN];
  uint8_t pattern[PATTERN_MAX_POINTS];
  uint8_t visited[9];
  size_t pattern_len = 0;
  int attempts_left = 8;
  int is_touching = 0;
  char status[48];

  status[0] = '\0';

  if (read_tokens_bin_salt(salt, loaded_path) < 0)
    return -1;

  memset(visited, 0, sizeof(visited));

  while (attempts_left > 0) {
    int kd;
    int ku;
    int kh;
    touchPosition touch;

    scanKeys();
    kd = keysDown();
    ku = keysUp();
    kh = keysHeld();

    if (kd & KEY_START)
      exit(0);
#ifdef KEY_POWER
    if (kd & KEY_POWER)
      exit(0);
#endif

    if (kh & KEY_TOUCH) {
      int idx;
      touchRead(&touch);
      idx = touch_to_pattern_cell(touch.px, touch.py);
      is_touching = 1;
      if ((idx >= 0) && (idx < 9) && !visited[idx] &&
          (pattern_len < PATTERN_MAX_POINTS)) {
        visited[idx] = 1;
        pattern[pattern_len++] = (uint8_t)idx;
      }
    } else if (is_touching && (ku & KEY_TOUCH)) {
      is_touching = 0;

      if (pattern_len < PATTERN_MIN_POINTS) {
        strncpy(status, "Pattern too short", sizeof(status) - 1);
        status[sizeof(status) - 1] = '\0';
      } else {
        uint8_t try_enc[20];
        uint8_t try_mac[20];
        size_t tmp_count = 0;
        const char *tmp_path = NULL;

        derive_keys_from_pattern(pattern, pattern_len, salt, try_enc, try_mac);
        if (load_tokens_bin_with_keys(tokens, &tmp_count, &tmp_path, try_enc,
                                      try_mac) == 0) {
          memcpy(g_enc_key, try_enc, sizeof(g_enc_key));
          memcpy(g_mac_key, try_mac, sizeof(g_mac_key));
          g_has_unlocked_keys = 1;
          *count = tmp_count;
          *loaded_path = tmp_path;
          return 0;
        }

        attempts_left--;
        strncpy(status, "Wrong pattern", sizeof(status) - 1);
        status[sizeof(status) - 1] = '\0';
      }

      memset(visited, 0, sizeof(visited));
      memset(pattern, 0, sizeof(pattern));
      pattern_len = 0;
    }

    draw_unlock_screen(visited, pattern_len, attempts_left, status);
    swiWaitForVBlank();
  }

  return -2;
}

static int __attribute__((unused))
load_tokens(token_t *tokens, size_t *count, const char **loaded_path,
            int *time_correction_seconds) {
  static const char *paths[] = {
      "sd:/totp/tokens.txt",
      "fat:/totp/tokens.txt",
      "/totp/tokens.txt",
  };

  FILE *fp = NULL;
  char line[LINE_BUF_LEN];
  size_t line_no;
  size_t idx;

  *count = 0;
  *loaded_path = NULL;

  for (idx = 0; idx < (sizeof(paths) / sizeof(paths[0])); idx++) {
    fp = fopen(paths[idx], "r");
    if (fp != NULL) {
      *loaded_path = paths[idx];
      break;
    }
  }

  if (fp == NULL)
    return -1;

  line_no = 0;
  while (fgets(line, sizeof(line), fp) != NULL) {
    char *cur;
    char *label;
    char *secret;
    char *interval_s;
    char *start_s;
    token_t token;
    unsigned long interval_ul;

    line_no++;
    cur = trim(line);

    if ((cur[0] == '\0') || (cur[0] == '#'))
      continue;

    if (parse_time_correction_line(cur, time_correction_seconds))
      continue;

    label = trim(strtok(cur, "|"));
    secret = trim(strtok(NULL, "|"));
    interval_s = strtok(NULL, "|");
    start_s = strtok(NULL, "|");

    if ((label == NULL) || (secret == NULL))
      continue;

    if (strlen(label) > MAX_LABEL_LEN)
      continue;

    memset(&token, 0, sizeof(token));
    strncpy(token.label, label, MAX_LABEL_LEN);
    token.interval = 30;
    token.t0 = 0;

    if (interval_s != NULL) {
      interval_s = trim(interval_s);
      interval_ul = strtoul(interval_s, NULL, 0);
      if (interval_ul > 0)
        token.interval = (uint32_t)interval_ul;
    }

    if (start_s != NULL) {
      start_s = trim(start_s);
      token.t0 = strtoll(start_s, NULL, 0);
    }

    if (base32_decode(secret, token.key, sizeof(token.key), &token.key_len) < 0)
      continue;

    if (*count >= MAX_TOKENS)
      break;

    tokens[*count] = token;
    (*count)++;
  }

  fclose(fp);
  return 0;
}

static void draw_ui(const token_t *tokens, size_t count, size_t selected,
                    const char *loaded_path __attribute__((unused)),
                    int time_correction_seconds) {
  size_t i;
  size_t start;
  size_t end;
  size_t row_cost[MAX_TOKENS];
  size_t used_rows;
  int list_top_row;
  int list_bottom_row;
  int available_rows;
  const int top_info_rows = UI_TOP_INFO_ROWS;
  const int top_padding_rows = UI_LIST_TOP_PADDING_ROWS;
  const int code_row = UI_CODE_ROW;
  const int gap_before_code = UI_GAP_BEFORE_CODE_ROWS;
  const int label_cols = UI_LABEL_COLS;
  const int service_gap_rows = UI_SERVICE_GAP_ROWS;
  int row_cursor;
  time_t raw_now;
  time_t now;
  int64_t corrected_now;

  raw_now = time(NULL);
  corrected_now = (int64_t)raw_now + (int64_t)time_correction_seconds;
  now = (time_t)corrected_now;

  /* TOP SCREEN: Detailed info */
  consoleSelect(&g_top_console);
  iprintf("\x1b[2J");
  top_at(1, 1, "DSi TOTP");
  top_at(3, 1, "Raw unix:   %ld", (long)raw_now);
  top_at(4, 1, "Adjusted:   %ld", (long)now);
  top_at(5, 1, "Correction: %+d", time_correction_seconds);

  if (count == 0) {
    top_at(6, 1, "No tokens loaded");
    top_at(12, 1, "A: reload");
    top_at(13, 1, "Y:scan QR");
    top_at(14, 1, "X:delete (none)");
    clear_top_row(18);
    if (g_status_msg[0] != '\0')
      top_at(18, 1, "%s", g_status_msg);
  } else {
    if (selected >= count)
      selected = 0;

    const token_t *tok = &tokens[selected];
    uint32_t code = compute_totp(tok, now);
    uint32_t remain;
    int64_t elapsed = (int64_t)now - tok->t0;
    uint64_t counter;

    if (elapsed < 0) {
      remain = tok->interval;
      counter = 0;
    } else {
      remain = tok->interval - ((uint32_t)elapsed % tok->interval);
      counter = (uint64_t)(elapsed / (int64_t)tok->interval);
    }

    top_at(7, 1, "Code:     %06lu", (unsigned long)code);
    top_at(8, 1, "Refresh:  %lus", (unsigned long)remain);
    top_at(9, 1, "Counter:  %llu", (unsigned long long)counter);
    top_at(10, 1, "Interval: %lu", (unsigned long)tok->interval);

    top_at(12, 1, "UP/DOWN: select");
    top_at(13, 1, "A: reload");
    top_at(14, 1, "X:delete selected  Y:scan QR");
    clear_top_row(18);
    if (g_status_msg[0] != '\0')
      top_at(18, 1, "%s", g_status_msg);
    top_at(22, 13, "%06lu", (unsigned long)code);
  }

  /* BOTTOM SCREEN: Info at top, selection in middle, code at bottom */
  consoleSelect(&g_bottom_console);
  printf("\x1b[2J");
  
  if (count > 0) {
    if (selected >= count)
      selected = 0;

    const token_t *tok = &tokens[selected];
    uint32_t code = compute_totp(tok, now);
    uint32_t remain;
    int64_t elapsed = (int64_t)now - tok->t0;

    if (elapsed < 0) {
      remain = tok->interval;
    } else {
      remain = tok->interval - ((uint32_t)elapsed % tok->interval);
    }

    /* Info at top */
    bottom_at(1, 1, "Refresh: %lus", (unsigned long)remain);

    /* Dynamic selection area with top/bottom padding and wrapped labels */
    list_top_row = 1 + top_info_rows + top_padding_rows;
    list_bottom_row = code_row - gap_before_code - 1;
    available_rows = list_bottom_row - list_top_row + 1;
    if (available_rows < 1)
      available_rows = 1;

    for (i = 0; i < count; i++) {
      size_t l = strlen(tokens[i].label);
      size_t lines = (l + (size_t)label_cols - 1) / (size_t)label_cols;
      if (lines == 0)
        lines = 1;
      row_cost[i] = lines;
    }

    start = selected;
    end = selected + 1;
    used_rows = row_cost[selected];

    for (i = 1; i < count; i++) {
      size_t up = (selected >= i) ? (selected - i) : count;
      size_t down = selected + i;
      int added = 0;

      if ((up < count) && (up < start) &&
          ((int)(used_rows + row_cost[up] + service_gap_rows) <=
           available_rows)) {
        start = up;
        used_rows += row_cost[up] + service_gap_rows;
        added = 1;
      }

      if ((down < count) && (down >= end) &&
          ((int)(used_rows + row_cost[down] + service_gap_rows) <=
           available_rows)) {
        end = down + 1;
        used_rows += row_cost[down] + service_gap_rows;
        added = 1;
      }

      if (!added && (up >= count) && (down >= count))
        break;
      if (!added && ((int)used_rows >= available_rows))
        break;
    }

    row_cursor = list_top_row;
    for (i = start; i < end; i++) {
      size_t line_idx;
      size_t label_len = strlen(tokens[i].label);

      for (line_idx = 0; line_idx < row_cost[i] && row_cursor <= list_bottom_row;
           line_idx++, row_cursor++) {
        size_t off = line_idx * (size_t)label_cols;
        size_t rem = (off < label_len) ? (label_len - off) : 0;
        size_t chunk = (rem > (size_t)label_cols) ? (size_t)label_cols : rem;

        clear_bottom_row(row_cursor);
        if (line_idx == 0) {
          bottom_at(row_cursor, 1, "%c%.*s", (i == selected) ? '>' : ' ',
                    (int)chunk, tokens[i].label + off);
        } else {
          bottom_at(row_cursor, 1, " %.*s", (int)chunk, tokens[i].label + off);
        }
      }

      if ((i + 1 < end) && (service_gap_rows > 0)) {
        int g;
        for (g = 0; (g < service_gap_rows) && (row_cursor <= list_bottom_row);
             g++, row_cursor++) {
          clear_bottom_row(row_cursor);
        }
      }
    }

    while (row_cursor <= list_bottom_row) {
      clear_bottom_row(row_cursor);
      row_cursor++;
    }

    /* Code centered with a bit of bottom padding */
    bottom_at(22, 13, "%06lu", (unsigned long)code);
  } else {
    bottom_at(1, 1, "No tokens loaded");
  }
}

static void reload_tokens_if_unlocked(token_t *tokens, size_t *token_count,
                                      const char **loaded_path,
                                      size_t *selected) {
  if (g_has_unlocked_keys) {
    (void)load_tokens_bin_with_keys(tokens, token_count, loaded_path, g_enc_key,
                                    g_mac_key);
  }

  if (*selected >= *token_count)
    *selected = 0;
}

int main(void) {
  token_t tokens[MAX_TOKENS];
  size_t token_count;
  size_t selected;
  const char *loaded_path;
  time_t last_second;
  int delete_armed = 0;
  char delete_label[MAX_LABEL_LEN + 1];

  videoSetMode(MODE_0_2D);
  videoSetModeSub(MODE_0_2D);
  vramSetBankA(VRAM_A_MAIN_BG);
  vramSetBankC(VRAM_C_SUB_BG);

  consoleInit(&g_top_console, 0, BgType_Text4bpp, BgSize_T_256x256, 31, 0, true,
              true);
  consoleInit(&g_bottom_console, 0, BgType_Text4bpp, BgSize_T_256x256, 31, 0,
              false, true);
  consoleSelect(&g_bottom_console);

  if (!fatInitDefault()) {
    consoleSelect(&g_top_console);
    iprintf("\x1b[2J\x1b[HSD init failed\n");
    iprintf("SD init failed\n");
    for (;;) {
      swiWaitForVBlank();
    }
  }

  token_count = 0;
  selected = 0;
  loaded_path = NULL;
  g_status_msg[0] = '\0';
  if (unlock_and_load_tokens(tokens, &token_count, &loaded_path) < 0) {
    consoleSelect(&g_top_console);
    iprintf("\x1b[2J\x1b[HUnlock failed\n");
    iprintf("Missing/invalid tokens.bin\n");
    for (;;) {
      swiWaitForVBlank();
    }
  }

  keysSetRepeat(20, 6);
  last_second = (time_t)-1;

  while (1) {
    int needs_redraw = 0;
    int pressed;
    int down;

    scanKeys();
    pressed = keysDown();
    down = keysDownRepeat();

    if (pressed & KEY_START)
      exit(0);
#ifdef KEY_POWER
    if (pressed & KEY_POWER)
      exit(0);
#endif

    if (down & KEY_UP) {
      if (token_count > 0) {
        delete_armed = 0;
        selected = (selected == 0) ? (token_count - 1) : (selected - 1);
        needs_redraw = 1;
      }
    }

    if (down & KEY_DOWN) {
      if (token_count > 0) {
        delete_armed = 0;
        selected = (selected + 1) % token_count;
        needs_redraw = 1;
      }
    }

    if (down & KEY_A) {
      delete_armed = 0;
      reload_tokens_if_unlocked(tokens, &token_count, &loaded_path, &selected);
      needs_redraw = 1;
    }

    if ((down & KEY_R) || (down & KEY_L)) {
      delete_armed = 0;
      reload_tokens_if_unlocked(tokens, &token_count, &loaded_path, &selected);
      needs_redraw = 1;
    }

    if (pressed & KEY_X) {
      if (delete_armed) {
        delete_armed = 0;
        g_status_msg[0] = '\0';
      } else if (token_count == 0) {
        snprintf(g_status_msg, sizeof(g_status_msg), "No entry to delete");
      } else {
        snprintf(delete_label, sizeof(delete_label), "%s", tokens[selected].label);
        delete_armed = 1;
        snprintf(g_status_msg, sizeof(g_status_msg), "Delete '%s' ? Press Y",
                 delete_label);
      }
      needs_redraw = 1;
    }

    if (pressed & KEY_Y) {
      if (delete_armed) {
        token_t check_tokens[MAX_TOKENS];
        size_t check_count = 0;
        const char *check_path = NULL;
        uint8_t salt[TOKEN_SALT_LEN];
        size_t idx = MAX_TOKENS;
        size_t j;

        delete_armed = 0;

        if (unlock_and_load_tokens(check_tokens, &check_count, &check_path) < 0) {
          snprintf(g_status_msg, sizeof(g_status_msg),
                   "Delete failed (unlock)");
        } else {
          const char *target_path =
              (check_path != NULL) ? check_path : loaded_path;

          for (j = 0; j < check_count; j++) {
            if (strcmp(check_tokens[j].label, delete_label) == 0) {
              idx = j;
              break;
            }
          }

          if (idx >= check_count) {
            snprintf(g_status_msg, sizeof(g_status_msg), "Entry already absent");
          } else if (read_tokens_bin_salt(salt, &check_path) < 0) {
            snprintf(g_status_msg, sizeof(g_status_msg), "Failed to read salt");
          } else {
            for (j = idx; j + 1 < check_count; j++)
              check_tokens[j] = check_tokens[j + 1];
            check_count--;

            if ((target_path == NULL) ||
                (rewrite_tokens_bin_with_keys(target_path, salt, g_enc_key,
                                             g_mac_key, check_tokens,
                                             check_count) < 0)) {
              snprintf(g_status_msg, sizeof(g_status_msg), "Failed to delete entry");
            } else {
              snprintf(g_status_msg, sizeof(g_status_msg), "Deleted: %s",
                       delete_label);
            }
          }

          reload_tokens_if_unlocked(tokens, &token_count, &loaded_path,
                                    &selected);
        }

        needs_redraw = 1;
      } else {
        char uri[320];
        token_t imported;
        size_t i;

        if (!g_has_unlocked_keys || (loaded_path == NULL)) {
          snprintf(g_status_msg, sizeof(g_status_msg), "Scan unavailable");
          needs_redraw = 1;
        } else if (scan_otpauth_qr(uri, sizeof(uri), g_status_msg,
                                    sizeof(g_status_msg)) == 0) {
          if (parse_otpauth_uri(uri, &imported, g_status_msg,
                                sizeof(g_status_msg)) < 0) {
            needs_redraw = 1;
          } else if (token_count >= MAX_TOKENS) {
            snprintf(g_status_msg, sizeof(g_status_msg), "Liste pleine (%d)",
                     MAX_TOKENS);
            needs_redraw = 1;
          } else {
            int duplicate = 0;
            for (i = 0; i < token_count; i++) {
              if (strcmp(tokens[i].label, imported.label) == 0) {
                duplicate = 1;
                break;
              }
            }

            if (duplicate) {
              snprintf(g_status_msg, sizeof(g_status_msg), "Label already present");
            } else if (append_token_bin_entry(loaded_path, &imported, g_enc_key,
                                              g_mac_key) < 0) {
              snprintf(g_status_msg, sizeof(g_status_msg),
                       "Failed to write to vault");
            } else {
              (void)load_tokens_bin_with_keys(tokens, &token_count, &loaded_path,
                                              g_enc_key, g_mac_key);
              if (selected >= token_count)
                selected = 0;
              snprintf(g_status_msg, sizeof(g_status_msg), "Scan OK: %s",
                       imported.label);
            }
            needs_redraw = 1;
          }
        } else {
          needs_redraw = 1;
        }
      }
    }

    {
      time_t now = time(NULL);
      if (needs_redraw || (now != last_second)) {
        draw_ui(tokens, token_count, selected, loaded_path,
                g_time_correction_seconds);
        last_second = now;
      }
    }

    swiWaitForVBlank();
  }
}
