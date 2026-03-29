/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char *k_config_paths[] = {
    "sd:/totp/settings.cfg",
    "fat:/totp/settings.cfg",
    "/totp/settings.cfg",
};

/*
 * Search order is aligned with vault loading paths so runtime settings follow
 * the same storage location conventions across different launch contexts.
 */

void app_config_set_defaults(app_config_t *cfg) {
  if (cfg == NULL)
    return;

  /* UTC by default, daylight saving disabled. */
  cfg->utc_offset_minutes = 0;
  cfg->dst_enabled = 0;
  cfg->failed_unlock_count = 0;
  cfg->lockout_until_epoch = 0;
}

int32_t app_config_compute_offset_seconds(const app_config_t *cfg) {
  int32_t minutes;

  if (cfg == NULL)
    return 0;

  minutes = cfg->utc_offset_minutes;
  if (cfg->dst_enabled)
    minutes += 60;

  /* App correction is applied as raw_time + correction.
     To represent local zone UTC+X relative to device UTC-like time,
     we must apply the opposite sign here. */
  return -(minutes * 60);
}

static int ensure_parent_dir(const char *path) {
  char dir[128];
  const char *slash;
  size_t n;

  if (path == NULL)
    return -1;

  slash = strrchr(path, '/');
  if (slash == NULL)
    return -1;

  n = (size_t)(slash - path);
  if ((n == 0) || (n >= sizeof(dir)))
    return -1;

  memcpy(dir, path, n);
  dir[n] = '\0';

  if (mkdir(dir, 0777) == 0)
    return 0;

  return (errno == EEXIST) ? 0 : -1;
}

int app_config_load(app_config_t *cfg, const char **loaded_path) {
  FILE *fp = NULL;
  size_t i;
  char line[128];
  int has_utc = 0;
  int has_dst = 0;
  int has_legacy = 0;
  int32_t legacy_seconds = 0;

  if (cfg == NULL)
    return -1;

  app_config_set_defaults(cfg);
  if (loaded_path != NULL)
    *loaded_path = NULL;

  for (i = 0; i < (sizeof(k_config_paths) / sizeof(k_config_paths[0])); i++) {
    fp = fopen(k_config_paths[i], "rb");
    if (fp != NULL) {
      if (loaded_path != NULL)
        *loaded_path = k_config_paths[i];
      break;
    }
  }

  if (fp == NULL)
    return -1;

  /* Tolerant line-by-line parse to preserve forward/backward compatibility. */
  while (fgets(line, sizeof(line), fp) != NULL) {
    long v;

    if ((line[0] == '#') || (line[0] == '\n') || (line[0] == '\r'))
      continue;

    if (sscanf(line, "utc_offset_minutes=%ld", &v) == 1) {
      cfg->utc_offset_minutes = (int32_t)v;
      has_utc = 1;
      continue;
    }

    if (sscanf(line, "dst_enabled=%ld", &v) == 1) {
      cfg->dst_enabled = (v != 0) ? 1 : 0;
      has_dst = 1;
      continue;
    }

    if (sscanf(line, "time_offset_seconds=%ld", &v) == 1) {
      legacy_seconds = (int32_t)v;
      has_legacy = 1;
      continue;
    }

    if (sscanf(line, "failed_unlock_count=%ld", &v) == 1) {
      cfg->failed_unlock_count = (v > 0) ? (uint32_t)v : 0;
      continue;
    }

    if (sscanf(line, "lockout_until_epoch=%ld", &v) == 1) {
      cfg->lockout_until_epoch = (v > 0) ? (int64_t)v : 0;
      continue;
    }
  }

  fclose(fp);

  if ((!has_utc || !has_dst) && has_legacy) {
    /* Backward compatibility with previous single-offset config. */
    cfg->utc_offset_minutes = legacy_seconds / 60;
    cfg->dst_enabled = 0;
  }

  if (cfg->utc_offset_minutes < (-12 * 60))
    cfg->utc_offset_minutes = -12 * 60;
  if (cfg->utc_offset_minutes > (14 * 60))
    cfg->utc_offset_minutes = 14 * 60;
  cfg->dst_enabled = cfg->dst_enabled ? 1 : 0;
  if (cfg->failed_unlock_count > 1000)
    cfg->failed_unlock_count = 1000;
  if (cfg->lockout_until_epoch < 0)
    cfg->lockout_until_epoch = 0;

  return 0;
}

int app_config_save(const app_config_t *cfg, const char **saved_path) {
  FILE *fp = NULL;
  size_t i;

  if (cfg == NULL)
    return -1;

  if (saved_path != NULL)
    *saved_path = NULL;

  for (i = 0; i < (sizeof(k_config_paths) / sizeof(k_config_paths[0])); i++) {
    if (ensure_parent_dir(k_config_paths[i]) < 0)
      continue;

    fp = fopen(k_config_paths[i], "wb");
    if (fp != NULL) {
      if (saved_path != NULL)
        *saved_path = k_config_paths[i];
      break;
    }
  }

  if (fp == NULL)
    return -1;

  fprintf(fp, "# NDS-TOTP runtime settings\n");
  fprintf(fp, "utc_offset_minutes=%ld\n", (long)cfg->utc_offset_minutes);
  fprintf(fp, "dst_enabled=%d\n", cfg->dst_enabled ? 1 : 0);
    fprintf(fp, "failed_unlock_count=%lu\n",
      (unsigned long)cfg->failed_unlock_count);
    fprintf(fp, "lockout_until_epoch=%lld\n",
      (long long)cfg->lockout_until_epoch);
  /* Keep legacy key for compatibility with old builds/tools. */
  fprintf(fp, "time_offset_seconds=%ld\n",
          (long)app_config_compute_offset_seconds(cfg));
  fclose(fp);
  return 0;
}
