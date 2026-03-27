#ifndef NDS_TOTP_CRYPTO_H
#define NDS_TOTP_CRYPTO_H

#include "app.h"
#include <stdio.h>

void derive_keys_from_pattern(const uint8_t *pattern, size_t pattern_len,
                              const uint8_t salt[TOKEN_SALT_LEN],
                              uint8_t enc_key[20], uint8_t mac_key[20]);

int load_tokens_bin_with_keys(token_t *tokens, size_t *count,
                              const char **loaded_path,
                              const uint8_t enc_key[20],
                              const uint8_t mac_key[20]);

int read_tokens_bin_salt(uint8_t out_salt[TOKEN_SALT_LEN],
                         const char **loaded_path);

int append_token_bin_entry(const char *bin_path, const token_t *token,
                           const uint8_t enc_key[20],
                           const uint8_t mac_key[20]);

int rewrite_tokens_bin_with_keys(const char *bin_path,
                                 const uint8_t salt[TOKEN_SALT_LEN],
                                 const uint8_t enc_key[20],
                                 const uint8_t mac_key[20],
                                 const token_t *tokens, size_t count);

#endif
