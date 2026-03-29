/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef NDS_TOTP_TOTP_H
#define NDS_TOTP_TOTP_H

#include "app.h"
#include <time.h>

/*
 * TOTP primitives shared by app and URI parser:
 * - HOTP/TOTP code computation
 * - base32 decode helper
 * - small parsing/trim helpers used by legacy paths
 */

uint32_t compute_totp(const token_t *token, time_t now);
int parse_time_correction_line(const char *line, int *value);
char *trim(char *s);
int base32_decode(const char *in, uint8_t *out, size_t out_cap, size_t *out_len);

#endif
