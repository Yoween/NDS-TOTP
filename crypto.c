#include "crypto.h"

#include <hmac/hmac.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void hmac20(const uint8_t *key, size_t key_len, const uint8_t *msg,
                   size_t msg_len, uint8_t out[20]) {
  size_t out_len = 20;
  hmac_sha1(key, key_len, msg, msg_len, out, &out_len);
}

void derive_keys_from_pattern(const uint8_t *pattern, size_t pattern_len,
                              const uint8_t salt[TOKEN_SALT_LEN],
                              uint8_t enc_key[20], uint8_t mac_key[20]) {
  uint8_t seed[20];
  uint8_t msg[TOKEN_SALT_LEN + 2];
  uint16_t i;

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

static uint16_t read_u16_le(FILE *fp, int *ok) {
  uint8_t b[2];
  if ((*ok) && (fread(b, 1, 2, fp) != 2))
    *ok = 0;
  return (uint16_t)b[0] | ((uint16_t)b[1] << 8);
}

static uint32_t read_u32_le(FILE *fp, int *ok) {
  uint8_t b[4];
  if ((*ok) && (fread(b, 1, 4, fp) != 4))
    *ok = 0;
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
         ((uint32_t)b[3] << 24);
}

static int64_t read_i64_le(FILE *fp, int *ok) {
  uint8_t b[8];
  uint64_t v;

  if ((*ok) && (fread(b, 1, 8, fp) != 8))
    *ok = 0;

  v = (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
      ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) |
      ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) |
      ((uint64_t)b[7] << 56);
  return (int64_t)v;
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

static void make_entry_nonce(const uint8_t enc_key[20],
                             uint8_t nonce[TOKEN_NONCE_LEN]) {
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

int load_tokens_bin_with_keys(token_t *tokens, size_t *count,
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

int read_tokens_bin_salt(uint8_t out_salt[TOKEN_SALT_LEN],
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

int append_token_bin_entry(const char *bin_path, const token_t *token,
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

int rewrite_tokens_bin_with_keys(const char *bin_path,
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
