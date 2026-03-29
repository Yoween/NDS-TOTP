/* SPDX-License-Identifier: BSD-3-Clause */

/*
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2019-2025, Michael Santos <michael.santos@gmail.com>
 *  Copyright (c) 2015, David M. Syzdek <david@syzdek.net>
 *  All rights reserved.
 */

#include "totp.h"

#include <hmac/hmac.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* RFC 6238-compatible TOTP primitives used by both app and packer paths. */

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

int parse_time_correction_line(const char *line, int *value) {
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



char *trim(char *s) {
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

int base32_decode(const char *in, uint8_t *out, size_t out_cap,
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

uint32_t compute_totp(const token_t *token, time_t now) {
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

  /* HOTP moving factor for current time window. */
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
