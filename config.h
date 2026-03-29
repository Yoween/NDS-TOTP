/* SPDX-License-Identifier: GPL-3.0-or-later */

#ifndef NDS_TOTP_CONFIG_H
#define NDS_TOTP_CONFIG_H

#include <stdint.h>

/*
 * Persistent runtime settings stored on SD:
 * - UTC offset in minutes
 * - DST toggle
 *
 * `app_config_compute_offset_seconds` converts these settings into the
 * correction applied by the UI (`raw_time + correction`).
 */

typedef struct app_config_s {
  int32_t utc_offset_minutes;
  int dst_enabled;
  uint32_t failed_unlock_count;
  int64_t lockout_until_epoch;
} app_config_t;

void app_config_set_defaults(app_config_t *cfg);
int app_config_load(app_config_t *cfg, const char **loaded_path);
int app_config_save(const app_config_t *cfg, const char **saved_path);
int32_t app_config_compute_offset_seconds(const app_config_t *cfg);

#endif
