#ifndef NDS_TOTP_CAMERA_SCAN_H
#define NDS_TOTP_CAMERA_SCAN_H

#include "app.h"

int scan_otpauth_qr(app_state_t *app, char *out_uri, size_t out_cap,
                    char *err, size_t err_cap);

#endif
