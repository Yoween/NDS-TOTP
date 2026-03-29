/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef NDS_TOTP_QR_H
#define NDS_TOTP_QR_H

#include "app.h"

/* Parses `otpauth://totp/...` URIs into validated token entries. */

int parse_otpauth_uri(const char *uri, token_t *out, char *err, size_t err_cap);

#endif
