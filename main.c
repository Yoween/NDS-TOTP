/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "camera_scan.h"
#include "config.h"
#include "crypto.h"
#include "gui.h"
#include "qr.h"

#include <fat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TZ_MIN_MINUTES (-12 * 60)
#define TZ_MAX_MINUTES (14 * 60)
#define LOCKOUT_THRESHOLD 3
#define LOCKOUT_BASE_SECONDS 30
#define LOCKOUT_MAX_SECONDS 3600

/* Applies persisted settings to the in-memory runtime state used by the UI. */
static void apply_config_to_app(app_state_t *app, const app_config_t *cfg) {
  if ((app == NULL) || (cfg == NULL))
    return;

  app->tz_offset_minutes = (int)cfg->utc_offset_minutes;
  app->dst_enabled = cfg->dst_enabled ? 1 : 0;
  app->time_correction_seconds = (int)app_config_compute_offset_seconds(cfg);
}

static void status_from_timezone(app_state_t *app, const char *suffix) {
  int m;
  char sign;

  if (app == NULL)
    return;

  m = app->tz_offset_minutes;
  sign = (m < 0) ? '-' : '+';
  if (m < 0)
    m = -m;

  snprintf(app->status_msg, sizeof(app->status_msg),
           "TZ UTC%c%d:%02d DST:%s%s", sign, m / 60, m % 60,
           app->dst_enabled ? "on" : "off", (suffix != NULL) ? suffix : "");
}

static void secure_zero(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len-- > 0)
    *p++ = 0;
}

static void secure_exit(app_state_t *app, token_t *tokens, size_t token_count,
                        char *delete_label, size_t delete_label_cap) {
  size_t i;

  if (tokens != NULL) {
    for (i = 0; i < token_count; i++)
      secure_zero(&tokens[i], sizeof(tokens[i]));
  }

  if (delete_label != NULL)
    secure_zero(delete_label, delete_label_cap);

  if (app != NULL)
    secure_zero(app, sizeof(*app));

  exit(0);
}

static void reload_tokens_if_unlocked(app_state_t *app, token_t *tokens,
                                      size_t *token_count,
                                      const char **loaded_path,
                                      size_t *selected) {
  if (app->has_unlocked_keys) {
    (void)load_tokens_bin_with_keys(tokens, token_count, loaded_path,
                                    app->enc_key, app->mac_key);
  }

  if (*selected >= *token_count)
    *selected = 0;
}

int main(void) {
  app_state_t app;
  token_t tokens[MAX_TOKENS];
  size_t token_count;
  size_t selected;
  const char *loaded_path;
  const char *settings_path = NULL;
  time_t last_second;
  int delete_armed = 0;
  char delete_label[MAX_LABEL_LEN + 1];
  app_config_t cfg;
  time_t now;

  memset(&app, 0, sizeof(app));
  gui_init_text_consoles(&app);
  consoleSelect(&app.bottom_console);

  if (!fatInitDefault()) {
    consoleSelect(&app.top_console);
    iprintf("\x1b[2J\x1b[HSD init failed\n");
    iprintf("SD init failed\n");
    for (;;) {
      swiWaitForVBlank();
    }
  }

  token_count = 0;
  selected = 0;
  loaded_path = NULL;
  app.status_msg[0] = '\0';

  /* Load persisted runtime settings (offset, etc.) if present. */
  app_config_set_defaults(&cfg);
  (void)app_config_load(&cfg, &settings_path);
  apply_config_to_app(&app, &cfg);

  now = time(NULL);
  if ((cfg.lockout_until_epoch > 0) &&
      ((int64_t)now < cfg.lockout_until_epoch)) {
    long long remain = (long long)(cfg.lockout_until_epoch - (int64_t)now);
    if (remain < 1)
      remain = 1;

    consoleSelect(&app.top_console);
    iprintf("\x1b[2J\x1b[HUnlock temporarily blocked\n");
    iprintf("Try again in %lld sec\n", remain);
    iprintf("(persistent lockout)\n");
    for (;;) {
      swiWaitForVBlank();
    }
  }

  {
    int unlock_rc =
        gui_unlock_and_load_tokens(&app, tokens, &token_count, &loaded_path);
    if (unlock_rc == -3)
      secure_exit(&app, tokens, token_count, delete_label, sizeof(delete_label));
    if (unlock_rc == -4) {
      consoleSelect(&app.top_console);
      iprintf("\x1b[2J\x1b[HLegacy vault detected\n");
      iprintf("PIN is now mandatory\n");
      iprintf("Migrate with totp-pack\n");
      for (;;) {
        swiWaitForVBlank();
      }
    }
    if (unlock_rc == -2) {
      uint32_t extra;
      int lock_secs;

      if (cfg.failed_unlock_count < 1000)
        cfg.failed_unlock_count++;

      now = time(NULL);
      cfg.lockout_until_epoch = 0;
      if (cfg.failed_unlock_count >= LOCKOUT_THRESHOLD) {
        extra = cfg.failed_unlock_count - LOCKOUT_THRESHOLD;
        if (extra > 16)
          extra = 16;

        lock_secs = LOCKOUT_BASE_SECONDS;
        lock_secs <<= extra;
        if (lock_secs > LOCKOUT_MAX_SECONDS)
          lock_secs = LOCKOUT_MAX_SECONDS;

        cfg.lockout_until_epoch = (int64_t)now + (int64_t)lock_secs;
      }
      (void)app_config_save(&cfg, &settings_path);

      consoleSelect(&app.top_console);
      iprintf("\x1b[2J\x1b[HUnlock failed\n");
      if (cfg.lockout_until_epoch > (int64_t)now) {
        iprintf("Locked for %lld sec\n",
                (long long)(cfg.lockout_until_epoch - (int64_t)now));
      } else {
        iprintf("Try again\n");
      }
      for (;;) {
        swiWaitForVBlank();
      }
    }
    if (unlock_rc < 0) {
    consoleSelect(&app.top_console);
    iprintf("\x1b[2J\x1b[HUnlock failed\n");
    iprintf("Missing/invalid tokens.bin\n");
    for (;;) {
      swiWaitForVBlank();
    }
    }

    if ((cfg.failed_unlock_count != 0) || (cfg.lockout_until_epoch != 0)) {
      cfg.failed_unlock_count = 0;
      cfg.lockout_until_epoch = 0;
      (void)app_config_save(&cfg, &settings_path);
    }
  }

  keysSetRepeat(20, 6);
  last_second = (time_t)-1;

  /* Main event/render loop (input, actions, redraw throttled per second). */
  while (1) {
    int needs_redraw = 0;
    int pressed;
    int down;

    scanKeys();
    pressed = keysDown();
    down = keysDownRepeat();

    if (pressed & KEY_START)
      secure_exit(&app, tokens, token_count, delete_label, sizeof(delete_label));
#ifdef KEY_POWER
    if (pressed & KEY_POWER)
      secure_exit(&app, tokens, token_count, delete_label, sizeof(delete_label));
#endif

    if (down & KEY_UP) {
      if (token_count > 0) {
        delete_armed = 0;
        selected = (selected == 0) ? (token_count - 1) : (selected - 1);
        needs_redraw = 1;
      }
    }

    if (down & KEY_DOWN) {
      if (token_count > 0) {
        delete_armed = 0;
        selected = (selected + 1) % token_count;
        needs_redraw = 1;
      }
    }

    if (down & KEY_A) {
      delete_armed = 0;
      reload_tokens_if_unlocked(&app, tokens, &token_count, &loaded_path,
                                &selected);
      needs_redraw = 1;
    }

    if (pressed & KEY_L) {
      delete_armed = 0;
      cfg.utc_offset_minutes -= 60;
      if (cfg.utc_offset_minutes < TZ_MIN_MINUTES)
        cfg.utc_offset_minutes = TZ_MAX_MINUTES;
      apply_config_to_app(&app, &cfg);
      if (app_config_save(&cfg, &settings_path) == 0) {
        status_from_timezone(&app, " (saved)");
      } else {
        status_from_timezone(&app, " (save failed)");
      }
      needs_redraw = 1;
    }

    if (pressed & KEY_R) {
      delete_armed = 0;
      cfg.utc_offset_minutes += 60;
      if (cfg.utc_offset_minutes > TZ_MAX_MINUTES)
        cfg.utc_offset_minutes = TZ_MIN_MINUTES;
      apply_config_to_app(&app, &cfg);
      if (app_config_save(&cfg, &settings_path) == 0) {
        status_from_timezone(&app, " (saved)");
      } else {
        status_from_timezone(&app, " (save failed)");
      }
      needs_redraw = 1;
    }

    if (pressed & KEY_SELECT) {
      delete_armed = 0;
      cfg.dst_enabled = cfg.dst_enabled ? 0 : 1;
      apply_config_to_app(&app, &cfg);
      if (app_config_save(&cfg, &settings_path) == 0) {
        status_from_timezone(&app, " (saved)");
      } else {
        status_from_timezone(&app, " (save failed)");
      }
      needs_redraw = 1;
    }

    if (pressed & KEY_X) {
      if (delete_armed) {
        delete_armed = 0;
        app.status_msg[0] = '\0';
      } else if (token_count == 0) {
        snprintf(app.status_msg, sizeof(app.status_msg), "No entry to delete");
      } else {
        snprintf(delete_label, sizeof(delete_label), "%s", tokens[selected].label);
        delete_armed = 1;
        snprintf(app.status_msg, sizeof(app.status_msg), "Delete '%s' ? Press Y",
                 delete_label);
      }
      needs_redraw = 1;
    }

    if (pressed & KEY_Y) {
      if (delete_armed) {
        token_t check_tokens[MAX_TOKENS];
        size_t check_count = 0;
        const char *check_path = NULL;
        vault_meta_t meta;
        size_t idx = MAX_TOKENS;
        size_t j;

        delete_armed = 0;

        {
          int unlock_rc = gui_unlock_and_load_tokens(&app, check_tokens,
                                                     &check_count, &check_path);
          if (unlock_rc == -3)
            secure_exit(&app, tokens, token_count, delete_label,
                        sizeof(delete_label));
          if (unlock_rc < 0) {
          snprintf(app.status_msg, sizeof(app.status_msg),
                   "Delete failed (unlock)");
          } else {
          const char *target_path = (check_path != NULL) ? check_path : loaded_path;

          for (j = 0; j < check_count; j++) {
            if (strcmp(check_tokens[j].label, delete_label) == 0) {
              idx = j;
              break;
            }
          }

          if (idx >= check_count) {
            snprintf(app.status_msg, sizeof(app.status_msg), "Entry already absent");
          } else if (read_tokens_bin_meta(&meta, &check_path) < 0) {
            snprintf(app.status_msg, sizeof(app.status_msg),
                     "Failed to read vault meta");
          } else {
            for (j = idx; j + 1 < check_count; j++)
              check_tokens[j] = check_tokens[j + 1];
            check_count--;

            if ((target_path == NULL) ||
                (rewrite_tokens_bin_with_keys_meta(target_path, &meta,
                                                   app.enc_key, app.mac_key,
                                                   check_tokens, check_count) <
                 0)) {
              snprintf(app.status_msg, sizeof(app.status_msg),
                       "Failed to delete entry");
            } else {
              snprintf(app.status_msg, sizeof(app.status_msg), "Deleted: %s",
                       delete_label);
            }
          }

          reload_tokens_if_unlocked(&app, tokens, &token_count, &loaded_path,
                                    &selected);
          }
        }

        needs_redraw = 1;
      } else {
        char uri[320];
        token_t imported;
        size_t i;

        if (!app.has_unlocked_keys || (loaded_path == NULL)) {
          snprintf(app.status_msg, sizeof(app.status_msg), "Scan unavailable");
          needs_redraw = 1;
        } else if (scan_otpauth_qr(&app, uri, sizeof(uri), app.status_msg,
                                   sizeof(app.status_msg)) == 0) {
          if (parse_otpauth_uri(uri, &imported, app.status_msg,
                                sizeof(app.status_msg)) < 0) {
            needs_redraw = 1;
          } else if (token_count >= MAX_TOKENS) {
            snprintf(app.status_msg, sizeof(app.status_msg), "Liste pleine (%d)",
                     MAX_TOKENS);
            needs_redraw = 1;
          } else {
            int duplicate = 0;
            for (i = 0; i < token_count; i++) {
              if (strcmp(tokens[i].label, imported.label) == 0) {
                duplicate = 1;
                break;
              }
            }

            if (duplicate) {
              snprintf(app.status_msg, sizeof(app.status_msg),
                       "Label already present");
            } else if (append_token_bin_entry(loaded_path, &imported, app.enc_key,
                                              app.mac_key) < 0) {
              snprintf(app.status_msg, sizeof(app.status_msg),
                       "Failed to write to vault");
            } else {
              (void)load_tokens_bin_with_keys(tokens, &token_count, &loaded_path,
                                              app.enc_key, app.mac_key);
              if (selected >= token_count)
                selected = 0;
              snprintf(app.status_msg, sizeof(app.status_msg), "Scan OK: %s",
                       imported.label);
            }
            needs_redraw = 1;
          }
        } else {
          needs_redraw = 1;
        }
      }
    }

    {
      time_t now = time(NULL);
      if (needs_redraw || (now != last_second)) {
        gui_draw_ui(&app, tokens, token_count, selected);
        last_second = now;
      }
    }

    swiWaitForVBlank();
  }
}
