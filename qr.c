#include "qr.h"

#include "totp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

int parse_otpauth_uri(const char *uri, token_t *out, char *err, size_t err_cap) {
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
