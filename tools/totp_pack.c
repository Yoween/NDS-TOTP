#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <hmac/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TOKEN_BIN_MAGIC "NTB1"
#define TOKEN_BIN_VERSION 1
#define TOKEN_SALT_LEN 16
#define TOKEN_NONCE_LEN 8
#define TOKEN_TAG_LEN 16
#define PATTERN_MAX_POINTS 9
#define KDF_ROUNDS 2048
#define MAX_LABEL_LEN 63
#define MAX_KEY_LEN 64

static const int8_t base32_vals[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    14, 11, 26, 27, 28, 29, 30, 31, 1,  -1, -1, -1, -1, 0,  -1, -1,
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1,
};

static int base32_decode(const char *in, uint8_t *out, size_t out_cap,
                         size_t *out_len) {
  size_t len = strlen(in);
  size_t pos;
  size_t keylen = 0;

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
  memcpy(&mac_buf[p], cipher, cipher_len);
  p += cipher_len;

  hmac20(mac_key, 20, mac_buf, p, out_tag);
}

static int parse_pattern(const char *s, uint8_t out[PATTERN_MAX_POINTS],
                         size_t *out_len) {
  size_t i;
  uint8_t used[9] = {0};
  size_t n = strlen(s);

  if ((n < 4) || (n > PATTERN_MAX_POINTS))
    return -1;

  for (i = 0; i < n; i++) {
    if ((s[i] < '1') || (s[i] > '9'))
      return -1;
    out[i] = (uint8_t)(s[i] - '1');
    if (used[out[i]])
      return -1;
    used[out[i]] = 1;
  }

  *out_len = n;
  return 0;
}

static int fill_random(uint8_t *buf, size_t len) {
  FILE *fp = fopen("/dev/urandom", "rb");
  if (fp == NULL)
    return -1;
  if (fread(buf, 1, len, fp) != len) {
    fclose(fp);
    return -1;
  }
  fclose(fp);
  return 0;
}

static int read_header(FILE *fp, uint8_t salt[TOKEN_SALT_LEN], uint16_t *count) {
  uint8_t magic[4];
  uint8_t version;
  uint8_t c[2];

  if ((fread(magic, 1, 4, fp) != 4) || (fread(&version, 1, 1, fp) != 1) ||
      (fread(salt, 1, TOKEN_SALT_LEN, fp) != TOKEN_SALT_LEN) ||
      (fread(c, 1, 2, fp) != 2)) {
    return -1;
  }

  if ((magic[0] != TOKEN_BIN_MAGIC[0]) || (magic[1] != TOKEN_BIN_MAGIC[1]) ||
      (magic[2] != TOKEN_BIN_MAGIC[2]) || (magic[3] != TOKEN_BIN_MAGIC[3]) ||
      (version != TOKEN_BIN_VERSION)) {
    return -1;
  }

  *count = (uint16_t)c[0] | ((uint16_t)c[1] << 8);
  return 0;
}

static int write_header(FILE *fp, const uint8_t salt[TOKEN_SALT_LEN],
                        uint16_t count) {
  uint8_t c[2];
  c[0] = (uint8_t)(count & 0xFF);
  c[1] = (uint8_t)((count >> 8) & 0xFF);

  if (fwrite(TOKEN_BIN_MAGIC, 1, 4, fp) != 4)
    return -1;
  if (fputc(TOKEN_BIN_VERSION, fp) == EOF)
    return -1;
  if (fwrite(salt, 1, TOKEN_SALT_LEN, fp) != TOKEN_SALT_LEN)
    return -1;
  if (fwrite(c, 1, 2, fp) != 2)
    return -1;

  return 0;
}

typedef struct vault_entry_s {
  char label[MAX_LABEL_LEN + 1];
  uint8_t key[MAX_KEY_LEN];
  size_t key_len;
  uint32_t interval;
  int64_t t0;
} vault_entry_t;

static uint32_t read_u32_le_buf(const uint8_t b[4]) {
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
         ((uint32_t)b[3] << 24);
}

static int64_t read_i64_le_buf(const uint8_t b[8]) {
  uint64_t v = (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
               ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) |
               ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) |
               ((uint64_t)b[7] << 56);
  return (int64_t)v;
}

static int load_decrypted_entries(FILE *fp, uint16_t count,
                                  const uint8_t enc_key[20],
                                  const uint8_t mac_key[20],
                                  vault_entry_t *entries, size_t max_entries,
                                  size_t *out_count) {
  uint16_t e;
  size_t n = 0;

  for (e = 0; e < count; e++) {
    uint8_t nonce[TOKEN_NONCE_LEN];
    uint8_t lens[2];
    uint8_t interval_le[4];
    uint8_t t0_le[8];
    uint8_t cipher[MAX_LABEL_LEN + MAX_KEY_LEN];
    uint8_t plain[MAX_LABEL_LEN + MAX_KEY_LEN];
    uint8_t tag[TOKEN_TAG_LEN];
    uint8_t expected_tag[20];
    uint8_t label_len;
    uint8_t key_len;
    uint32_t interval;
    int64_t t0;
    size_t payload_len;
    size_t i;

    if ((fread(nonce, 1, TOKEN_NONCE_LEN, fp) != TOKEN_NONCE_LEN) ||
        (fread(lens, 1, 2, fp) != 2) || (fread(interval_le, 1, 4, fp) != 4) ||
        (fread(t0_le, 1, 8, fp) != 8)) {
      return -1;
    }

    label_len = lens[0];
    key_len = lens[1];
    interval = read_u32_le_buf(interval_le);
    t0 = read_i64_le_buf(t0_le);
    payload_len = (size_t)label_len + (size_t)key_len;

    if ((label_len == 0) || (label_len > MAX_LABEL_LEN) || (key_len == 0) ||
        (key_len > MAX_KEY_LEN) || (payload_len > sizeof(cipher)) ||
        (interval == 0)) {
      return -1;
    }

    if ((fread(cipher, 1, payload_len, fp) != payload_len) ||
        (fread(tag, 1, TOKEN_TAG_LEN, fp) != TOKEN_TAG_LEN)) {
      return -1;
    }

    compute_entry_tag(mac_key, label_len, key_len, interval, t0, nonce, cipher,
                      payload_len, expected_tag);
    for (i = 0; i < TOKEN_TAG_LEN; i++) {
      if (tag[i] != expected_tag[i])
        return -2;
    }

    if (n < max_entries) {
      memcpy(plain, cipher, payload_len);
      stream_xor(enc_key, nonce, plain, payload_len);

      memset(&entries[n], 0, sizeof(entries[n]));
      memcpy(entries[n].label, plain, label_len);
      entries[n].label[label_len] = '\0';
      memcpy(entries[n].key, plain + label_len, key_len);
      entries[n].key_len = key_len;
      entries[n].interval = interval;
      entries[n].t0 = t0;
      n++;
    }
  }

  *out_count = n;
  return 0;
}

static int write_vault_file(const char *file_path,
                            const uint8_t salt[TOKEN_SALT_LEN],
                            const uint8_t enc_key[20],
                            const uint8_t mac_key[20],
                            const vault_entry_t *entries, size_t count) {
  FILE *fp;
  size_t i;

  if (count > 65535)
    return -1;

  fp = fopen(file_path, "wb");
  if (fp == NULL)
    return -1;

  if (write_header(fp, salt, (uint16_t)count) < 0) {
    fclose(fp);
    return -1;
  }

  for (i = 0; i < count; i++) {
    uint8_t nonce[TOKEN_NONCE_LEN];
    uint8_t plain[MAX_LABEL_LEN + MAX_KEY_LEN];
    uint8_t cipher[MAX_LABEL_LEN + MAX_KEY_LEN];
    uint8_t tag[20];
    uint8_t lens[2];
    uint8_t interval_le[4];
    uint8_t t0_le[8];
    size_t label_len = strlen(entries[i].label);
    size_t payload_len;
    size_t j;

    if ((label_len == 0) || (label_len > MAX_LABEL_LEN) ||
        (entries[i].key_len == 0) || (entries[i].key_len > MAX_KEY_LEN) ||
        (entries[i].interval == 0)) {
      fclose(fp);
      return -1;
    }

    payload_len = label_len + entries[i].key_len;
    memcpy(plain, entries[i].label, label_len);
    memcpy(plain + label_len, entries[i].key, entries[i].key_len);
    memcpy(cipher, plain, payload_len);

    if (fill_random(nonce, sizeof(nonce)) < 0) {
      fclose(fp);
      return -1;
    }

    stream_xor(enc_key, nonce, cipher, payload_len);
    compute_entry_tag(mac_key, (uint8_t)label_len, (uint8_t)entries[i].key_len,
                      entries[i].interval, entries[i].t0, nonce, cipher,
                      payload_len, tag);

    lens[0] = (uint8_t)label_len;
    lens[1] = (uint8_t)entries[i].key_len;
    interval_le[0] = (uint8_t)(entries[i].interval & 0xFF);
    interval_le[1] = (uint8_t)((entries[i].interval >> 8) & 0xFF);
    interval_le[2] = (uint8_t)((entries[i].interval >> 16) & 0xFF);
    interval_le[3] = (uint8_t)((entries[i].interval >> 24) & 0xFF);
    for (j = 0; j < 8; j++)
      t0_le[j] = (uint8_t)(((uint64_t)entries[i].t0 >> (8 * j)) & 0xFF);

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

static int find_label_index(const vault_entry_t *entries, size_t count,
                            const char *label) {
  size_t i;
  for (i = 0; i < count; i++) {
    if (strcmp(entries[i].label, label) == 0)
      return (int)i;
  }
  return -1;
}

static int sanitize_label(const char *in, char *out, size_t out_cap) {
  size_t i;
  size_t j = 0;
  int last_space = 1;

  if ((in == NULL) || (out == NULL) || (out_cap == 0))
    return -1;

  for (i = 0; in[i] != '\0'; i++) {
    unsigned char ch = (unsigned char)in[i];

    if ((ch < 32) || (ch == 127)) {
      if (!last_space) {
        if (j + 1 >= out_cap)
          return -1;
        out[j++] = ' ';
        last_space = 1;
      }
      continue;
    }

    if (ch == '\t')
      ch = ' ';

    if (ch == ' ') {
      if (last_space)
        continue;
      if (j + 1 >= out_cap)
        return -1;
      out[j++] = ' ';
      last_space = 1;
      continue;
    }

    if (j + 1 >= out_cap)
      return -1;
    out[j++] = (char)ch;
    last_space = 0;
  }

  while ((j > 0) && (out[j - 1] == ' '))
    j--;

  if (j == 0)
    return -1;

  out[j] = '\0';
  return 0;
}

static int read_yes_confirmation(void) {
  char line[64];
  char norm[16];
  size_t i;
  size_t j = 0;

  if (fgets(line, sizeof(line), stdin) == NULL)
    return 0;

  for (i = 0; line[i] != '\0'; i++) {
    unsigned char ch = (unsigned char)line[i];
    if ((ch == '\r') || (ch == '\n'))
      break;
    if ((ch == ' ') || (ch == '\t'))
      continue;
    if (j + 1 < sizeof(norm))
      norm[j++] = (char)tolower(ch);
  }
  norm[j] = '\0';

  return (strcmp(norm, "y") == 0) || (strcmp(norm, "yes") == 0);
}

int main(int argc, char **argv) {
  const char *cmd;
  const char *file_path;
  const char *pattern_s;
  const char *label = NULL;
  const char *new_label = NULL;
  char label_clean[MAX_LABEL_LEN + 1];
  char new_label_clean[MAX_LABEL_LEN + 1];
  const char *secret_b32 = NULL;
  uint32_t interval = 30;
  int64_t t0 = 0;
  uint8_t pattern[PATTERN_MAX_POINTS];
  size_t pattern_len = 0;
  uint8_t key_bin[MAX_KEY_LEN];
  size_t key_len = 0;
  uint8_t salt[TOKEN_SALT_LEN];
  uint8_t enc_key[20];
  uint8_t mac_key[20];
  vault_entry_t entries[256];
  vault_entry_t new_entry;
  FILE *fp;
  uint16_t count = 0;
  size_t entry_count = 0;
  int existing = 0;
  int assume_yes = 0;
  int idx;

  if (argc < 2) {
    fprintf(stderr,
            "Usage:\n"
            "  %s add <tokens.bin> <pattern> <label> <base32_secret> [interval] [t0]\n"
            "  %s set <tokens.bin> <pattern> <label> <base32_secret> [interval] [t0]\n"
            "  %s del <tokens.bin> <pattern> <label> [--yes]\n"
            "  %s rename <tokens.bin> <pattern> <old_label> <new_label>\n"
            "  %s list <tokens.bin> <pattern>\n"
            "(compat) %s <tokens.bin> <pattern> <label> <base32_secret> [interval] [t0]\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
    return 1;
  }

  cmd = argv[1];
  if ((strcmp(cmd, "add") == 0) || (strcmp(cmd, "set") == 0)) {
    if ((argc < 6) || (argc > 8)) {
      fprintf(stderr, "Invalid arguments for %s\n", cmd);
      return 1;
    }
    file_path = argv[2];
    pattern_s = argv[3];
    label = argv[4];
    secret_b32 = argv[5];
    if (argc >= 7)
      interval = (uint32_t)strtoul(argv[6], NULL, 10);
    if (argc >= 8)
      t0 = (int64_t)strtoll(argv[7], NULL, 10);
  } else if ((strcmp(cmd, "del") == 0) || (strcmp(cmd, "remove") == 0) ||
             (strcmp(cmd, "rm") == 0)) {
    cmd = "del";
    if ((argc != 5) && (argc != 6)) {
      fprintf(stderr, "Invalid arguments for del\n");
      return 1;
    }
    file_path = argv[2];
    pattern_s = argv[3];
    label = argv[4];
    if (argc == 6) {
      if (strcmp(argv[5], "--yes") == 0) {
        assume_yes = 1;
      } else {
        fprintf(stderr, "Unknown option for del: %s\n", argv[5]);
        return 1;
      }
    }
  } else if (strcmp(cmd, "rename") == 0) {
    if (argc != 6) {
      fprintf(stderr, "Invalid arguments for rename\n");
      return 1;
    }
    file_path = argv[2];
    pattern_s = argv[3];
    label = argv[4];
    new_label = argv[5];
  } else if (strcmp(cmd, "list") == 0) {
    if (argc != 4) {
      fprintf(stderr, "Invalid arguments for list\n");
      return 1;
    }
    file_path = argv[2];
    pattern_s = argv[3];
  } else {
    /* Backward compatibility: old syntax means add */
    if ((argc >= 5) && (argc <= 7)) {
      cmd = "add";
      file_path = argv[1];
      pattern_s = argv[2];
      label = argv[3];
      secret_b32 = argv[4];
      if (argc >= 6)
        interval = (uint32_t)strtoul(argv[5], NULL, 10);
      if (argc >= 7)
        t0 = (int64_t)strtoll(argv[6], NULL, 10);
    } else {
      fprintf(stderr,
              "Unknown command: %s\n"
              "Use one of: add, set, del, remove, rm, rename, list\n",
              cmd);
      return 1;
    }
  }

  if (parse_pattern(pattern_s, pattern, &pattern_len) < 0) {
    fprintf(stderr,
            "Invalid pattern. Use digits 1..9 without repetition (min 4).\n");
    return 1;
  }

  if ((strcmp(cmd, "add") == 0) || (strcmp(cmd, "set") == 0)) {
    if ((interval == 0) || (sanitize_label(label, label_clean, sizeof(label_clean)) <
                            0)) {
      fprintf(stderr, "Invalid interval or label length\n");
      return 1;
    }
    label = label_clean;
    if (base32_decode(secret_b32, key_bin, sizeof(key_bin), &key_len) < 0) {
      fprintf(stderr, "Invalid base32 secret\n");
      return 1;
    }
  } else if (strcmp(cmd, "rename") == 0) {
    if ((sanitize_label(label, label_clean, sizeof(label_clean)) < 0) ||
        (sanitize_label(new_label, new_label_clean, sizeof(new_label_clean)) <
         0)) {
      fprintf(stderr, "Invalid label/new_label\n");
      return 1;
    }
    label = label_clean;
    new_label = new_label_clean;
  }

  fp = fopen(file_path, "rb+");
  if (fp == NULL) {
    existing = 0;
    if ((strcmp(cmd, "list") == 0) || (strcmp(cmd, "del") == 0) ||
        (strcmp(cmd, "rename") == 0)) {
      fprintf(stderr, "File not found: %s\n", file_path);
      return 1;
    }

    if (fill_random(salt, sizeof(salt)) < 0) {
      fprintf(stderr, "Unable to get random salt\n");
      return 1;
    }
  } else {
    existing = 1;
    if (read_header(fp, salt, &count) < 0) {
      fprintf(stderr, "Invalid or unsupported tokens.bin\n");
      fclose(fp);
      return 1;
    }
    if (count > 256) {
      fprintf(stderr, "Too many entries in file (max 256 for tool)\n");
      fclose(fp);
      return 1;
    }
  }

  derive_keys_from_pattern(pattern, pattern_len, salt, enc_key, mac_key);

  if (existing) {
    if (load_decrypted_entries(fp, count, enc_key, mac_key, entries,
                               sizeof(entries) / sizeof(entries[0]),
                               &entry_count) < 0) {
      fprintf(stderr,
              "Wrong pattern for this vault, or file corrupted.\n"
              "All entries in one tokens.bin must use the same pattern.\n");
      fclose(fp);
      return 1;
    }
    fclose(fp);
  } else {
    entry_count = 0;
  }

  if (strcmp(cmd, "list") == 0) {
    size_t i;
    for (i = 0; i < entry_count; i++) {
      printf("%s | interval=%u | t0=%lld\n", entries[i].label,
             (unsigned)entries[i].interval, (long long)entries[i].t0);
    }
    return 0;
  }

  if (strcmp(cmd, "del") == 0) {
    idx = find_label_index(entries, entry_count, label);
    if (idx < 0) {
      fprintf(stderr, "Label not found: %s\n", label);
      return 1;
    }

    if (!assume_yes) {
      printf("Delete '%s' from %s? Type Y or yes: ", label, file_path);
      fflush(stdout);
      if (!read_yes_confirmation()) {
        fprintf(stderr, "Deletion cancelled.\n");
        return 1;
      }
    }

    for (; (size_t)idx + 1 < entry_count; idx++)
      entries[idx] = entries[idx + 1];
    entry_count--;
    if (write_vault_file(file_path, salt, enc_key, mac_key, entries,
                         entry_count) < 0) {
      fprintf(stderr, "Failed writing updated vault\n");
      return 1;
    }
    printf("Deleted '%s' from %s (count=%lu)\n", label, file_path,
           (unsigned long)entry_count);
    return 0;
  }

  if (strcmp(cmd, "rename") == 0) {
    int idx_new;

    idx = find_label_index(entries, entry_count, label);
    if (idx < 0) {
      fprintf(stderr, "Label not found: %s\n", label);
      return 1;
    }

    idx_new = find_label_index(entries, entry_count, new_label);
    if ((idx_new >= 0) && (idx_new != idx)) {
      fprintf(stderr, "Target label already exists: %s\n", new_label);
      return 1;
    }

    snprintf(entries[idx].label, sizeof(entries[idx].label), "%s", new_label);

    if (write_vault_file(file_path, salt, enc_key, mac_key, entries,
                         entry_count) < 0) {
      fprintf(stderr, "Failed writing updated vault\n");
      return 1;
    }

    printf("Renamed '%s' -> '%s' in %s (count=%lu)\n", label, new_label,
           file_path, (unsigned long)entry_count);
    return 0;
  }

  memset(&new_entry, 0, sizeof(new_entry));
  snprintf(new_entry.label, sizeof(new_entry.label), "%s", label);
  memcpy(new_entry.key, key_bin, key_len);
  new_entry.key_len = key_len;
  new_entry.interval = interval;
  new_entry.t0 = t0;

  idx = find_label_index(entries, entry_count, label);
  if (strcmp(cmd, "add") == 0) {
    if (idx >= 0) {
      fprintf(stderr,
              "Label '%s' already exists. Use 'set' to modify it.\n",
              label);
      return 1;
    }
    if (entry_count >= (sizeof(entries) / sizeof(entries[0]))) {
      fprintf(stderr, "Too many entries (max 256 for tool)\n");
      return 1;
    }
    entries[entry_count++] = new_entry;
  } else { /* set */
    if (idx >= 0) {
      entries[idx] = new_entry;
    } else {
      if (entry_count >= (sizeof(entries) / sizeof(entries[0]))) {
        fprintf(stderr, "Too many entries (max 256 for tool)\n");
        return 1;
      }
      entries[entry_count++] = new_entry;
    }
  }

  if (write_vault_file(file_path, salt, enc_key, mac_key, entries, entry_count) <
      0) {
    fprintf(stderr, "Failed writing vault\n");
    return 1;
  }

  printf("%s token '%s' in %s (count=%lu)\n",
         (strcmp(cmd, "add") == 0) ? "Added" : "Updated", label, file_path,
         (unsigned long)entry_count);
  return 0;
}
