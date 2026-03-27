#include "camera_scan.h"
#include "crypto.h"
#include "gui.h"
#include "qr.h"

#include <fat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
  time_t last_second;
  int delete_armed = 0;
  char delete_label[MAX_LABEL_LEN + 1];

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
  app.time_correction_seconds = -3600;

  if (gui_unlock_and_load_tokens(&app, tokens, &token_count, &loaded_path) < 0) {
    consoleSelect(&app.top_console);
    iprintf("\x1b[2J\x1b[HUnlock failed\n");
    iprintf("Missing/invalid tokens.bin\n");
    for (;;) {
      swiWaitForVBlank();
    }
  }

  keysSetRepeat(20, 6);
  last_second = (time_t)-1;

  while (1) {
    int needs_redraw = 0;
    int pressed;
    int down;

    scanKeys();
    pressed = keysDown();
    down = keysDownRepeat();

    if (pressed & KEY_START)
      exit(0);
#ifdef KEY_POWER
    if (pressed & KEY_POWER)
      exit(0);
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

    if ((down & KEY_R) || (down & KEY_L)) {
      delete_armed = 0;
      reload_tokens_if_unlocked(&app, tokens, &token_count, &loaded_path,
                                &selected);
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
        uint8_t salt[TOKEN_SALT_LEN];
        size_t idx = MAX_TOKENS;
        size_t j;

        delete_armed = 0;

        if (gui_unlock_and_load_tokens(&app, check_tokens, &check_count,
                                       &check_path) < 0) {
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
          } else if (read_tokens_bin_salt(salt, &check_path) < 0) {
            snprintf(app.status_msg, sizeof(app.status_msg), "Failed to read salt");
          } else {
            for (j = idx; j + 1 < check_count; j++)
              check_tokens[j] = check_tokens[j + 1];
            check_count--;

            if ((target_path == NULL) ||
                (rewrite_tokens_bin_with_keys(target_path, salt, app.enc_key,
                                              app.mac_key, check_tokens,
                                              check_count) < 0)) {
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
