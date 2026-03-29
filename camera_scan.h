/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef NDS_TOTP_CAMERA_SCAN_H
#define NDS_TOTP_CAMERA_SCAN_H

#include "app.h"

/* Camera-based QR capture entrypoint used by the main UI flow. */

int scan_otpauth_qr(app_state_t *app, char *out_uri, size_t out_cap,
                    char *err, size_t err_cap);

#endif
