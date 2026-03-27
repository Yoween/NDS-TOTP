#include "gui.h"

#include "crypto.h"
#include "totp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int touch_to_pattern_cell(int x, int y) {
  const int cell_w = SCREEN_WIDTH / TOUCH_CELL_W_DIV;
  const int cell_h = SCREEN_HEIGHT / TOUCH_CELL_H_DIV;
  const int grid_w = cell_w * 3;
  const int grid_h = cell_h * 3;
  const int left = (SCREEN_WIDTH - grid_w) / 2;
  const int top = (SCREEN_HEIGHT - grid_h) / 2;
  const int hit_w = (cell_w * TOUCH_HIT_W_PERCENT) / 100;
  const int hit_h = (cell_h * TOUCH_HIT_H_PERCENT) / 100;
  int col = 0;
  int row = 0;
  int best_dx;
  int best_dy;
  int i;

  best_dx = abs(x - (left + cell_w / 2));
  for (i = 1; i < 3; i++) {
    int cx = left + i * cell_w + cell_w / 2;
    int dx = abs(x - cx);
    if (dx < best_dx) {
      best_dx = dx;
      col = i;
    }
  }

  best_dy = abs(y - (top + cell_h / 2));
  for (i = 1; i < 3; i++) {
    int cy = top + i * cell_h + cell_h / 2;
    int dy = abs(y - cy);
    if (dy < best_dy) {
      best_dy = dy;
      row = i;
    }
  }

  if ((best_dx > hit_w) || (best_dy > hit_h))
    return -1;

  return row * 3 + col;
}

void gui_top_at(int row, int col, const char *fmt, ...) {
  char buf[128];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  iprintf("\x1b[%d;%dH%s", row, col, buf);
}

void gui_bottom_at(int row, int col, const char *fmt, ...) {
  char buf[128];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  printf("\x1b[%d;%dH%s", row, col, buf);
}

void gui_clear_bottom_row(int row) {
  gui_bottom_at(row, 1, "%*s", CONSOLE_COLS, "");
}

static void clear_top_row(int row) {
  gui_top_at(row, 1, "%*s", CONSOLE_COLS, "");
}

void gui_clear_status_row(void) {
  clear_top_row(18);
}

void gui_init_text_consoles(app_state_t *app) {
  videoSetMode(MODE_0_2D);
  videoSetModeSub(MODE_0_2D);
  vramSetBankA(VRAM_A_MAIN_BG);
  vramSetBankC(VRAM_C_SUB_BG);
  consoleInit(&app->top_console, 0, BgType_Text4bpp, BgSize_T_256x256, 31, 0,
              true, true);
  consoleInit(&app->bottom_console, 0, BgType_Text4bpp, BgSize_T_256x256, 31,
              0, false, true);
}

void gui_restore_text_consoles(app_state_t *app) { gui_init_text_consoles(app); }

static void draw_unlock_screen(app_state_t *app, const uint8_t visited[9],
                               size_t pattern_len, int attempts_left,
                               const char *status) {
  int r;
  int c;
  const int grid_top_row = UNLOCK_GRID_TOP_ROW;
  const int grid_left_col = UNLOCK_GRID_LEFT_COL;
  const int grid_row_step = UNLOCK_GRID_ROW_STEP;
  const int grid_col_step = UNLOCK_GRID_COL_STEP;

  consoleSelect(&app->top_console);
  iprintf("\x1b[2J");
  gui_top_at(1, 1, "NDS-TOTP LOCKED");
  gui_top_at(3, 1, "Draw 3x3 pattern");
  gui_top_at(4, 1, "on touch screen");
  gui_top_at(6, 1, "Tries left: %d", attempts_left);
  clear_top_row(7);
  if ((status != NULL) && (status[0] != '\0'))
    gui_top_at(7, 1, "%s", status);

  consoleSelect(&app->bottom_console);
  printf("\x1b[2J");
  gui_bottom_at(1, 1, "Draw unlock pattern");
  gui_bottom_at(2, 1, "Entered points: %lu", (unsigned long)pattern_len);

  for (r = 0; r < 3; r++) {
    for (c = 0; c < 3; c++) {
      int idx = r * 3 + c;
      int row = grid_top_row + (r * grid_row_step);
      int col = grid_left_col + (c * grid_col_step);
      gui_bottom_at(row, col, "[%c]", visited[idx] ? '*' : ' ');
    }
  }

  gui_bottom_at(23, 1, "START: quit");
}

int gui_unlock_and_load_tokens(app_state_t *app, token_t *tokens, size_t *count,
                               const char **loaded_path) {
  uint8_t salt[TOKEN_SALT_LEN];
  uint8_t pattern[PATTERN_MAX_POINTS];
  uint8_t visited[9];
  size_t pattern_len = 0;
  int attempts_left = 8;
  int is_touching = 0;
  char status[48];

  status[0] = '\0';

  if (read_tokens_bin_salt(salt, loaded_path) < 0)
    return -1;

  memset(visited, 0, sizeof(visited));

  while (attempts_left > 0) {
    int kd;
    int ku;
    int kh;
    touchPosition touch;

    scanKeys();
    kd = keysDown();
    ku = keysUp();
    kh = keysHeld();

    if (kd & KEY_START)
      exit(0);
#ifdef KEY_POWER
    if (kd & KEY_POWER)
      exit(0);
#endif

    if (kh & KEY_TOUCH) {
      int idx;
      touchRead(&touch);
      idx = touch_to_pattern_cell(touch.px, touch.py);
      is_touching = 1;
      if ((idx >= 0) && (idx < 9) && !visited[idx] &&
          (pattern_len < PATTERN_MAX_POINTS)) {
        visited[idx] = 1;
        pattern[pattern_len++] = (uint8_t)idx;
      }
    } else if (is_touching && (ku & KEY_TOUCH)) {
      is_touching = 0;

      if (pattern_len < PATTERN_MIN_POINTS) {
        strncpy(status, "Pattern too short", sizeof(status) - 1);
        status[sizeof(status) - 1] = '\0';
      } else {
        uint8_t try_enc[20];
        uint8_t try_mac[20];
        size_t tmp_count = 0;
        const char *tmp_path = NULL;

        derive_keys_from_pattern(pattern, pattern_len, salt, try_enc, try_mac);
        if (load_tokens_bin_with_keys(tokens, &tmp_count, &tmp_path, try_enc,
                                      try_mac) == 0) {
          memcpy(app->enc_key, try_enc, sizeof(app->enc_key));
          memcpy(app->mac_key, try_mac, sizeof(app->mac_key));
          app->has_unlocked_keys = 1;
          *count = tmp_count;
          *loaded_path = tmp_path;
          return 0;
        }

        attempts_left--;
        strncpy(status, "Wrong pattern", sizeof(status) - 1);
        status[sizeof(status) - 1] = '\0';
      }

      memset(visited, 0, sizeof(visited));
      memset(pattern, 0, sizeof(pattern));
      pattern_len = 0;
    }

    draw_unlock_screen(app, visited, pattern_len, attempts_left, status);
    swiWaitForVBlank();
  }

  return -2;
}

void gui_draw_ui(app_state_t *app, const token_t *tokens, size_t count,
                 size_t selected) {
  size_t i;
  size_t start;
  size_t end;
  size_t row_cost[MAX_TOKENS];
  size_t used_rows;
  int list_top_row;
  int list_bottom_row;
  int available_rows;
  const int top_info_rows = UI_TOP_INFO_ROWS;
  const int top_padding_rows = UI_LIST_TOP_PADDING_ROWS;
  const int code_row = UI_CODE_ROW;
  const int gap_before_code = UI_GAP_BEFORE_CODE_ROWS;
  const int label_cols = UI_LABEL_COLS;
  const int service_gap_rows = UI_SERVICE_GAP_ROWS;
  int row_cursor;
  time_t raw_now;
  time_t now;
  int64_t corrected_now;

  raw_now = time(NULL);
  corrected_now = (int64_t)raw_now + (int64_t)app->time_correction_seconds;
  now = (time_t)corrected_now;

  consoleSelect(&app->top_console);
  iprintf("\x1b[2J");
  gui_top_at(1, 1, "DSi TOTP");
  gui_top_at(3, 1, "Raw unix:   %ld", (long)raw_now);
  gui_top_at(4, 1, "Adjusted:   %ld", (long)now);
  gui_top_at(5, 1, "Correction: %+d", app->time_correction_seconds);

  if (count == 0) {
    gui_top_at(6, 1, "No tokens loaded");
    gui_top_at(12, 1, "A: reload");
    gui_top_at(13, 1, "Y:scan QR");
    gui_top_at(14, 1, "X:delete (none)");
    clear_top_row(18);
    if (app->status_msg[0] != '\0')
      gui_top_at(18, 1, "%s", app->status_msg);
  } else {
    const token_t *tok;
    uint32_t code;
    uint32_t remain;
    int64_t elapsed;
    uint64_t counter;

    if (selected >= count)
      selected = 0;

    tok = &tokens[selected];
    code = compute_totp(tok, now);
    elapsed = (int64_t)now - tok->t0;

    if (elapsed < 0) {
      remain = tok->interval;
      counter = 0;
    } else {
      remain = tok->interval - ((uint32_t)elapsed % tok->interval);
      counter = (uint64_t)(elapsed / (int64_t)tok->interval);
    }

    gui_top_at(7, 1, "Code:     %06lu", (unsigned long)code);
    gui_top_at(8, 1, "Refresh:  %lus", (unsigned long)remain);
    gui_top_at(9, 1, "Counter:  %llu", (unsigned long long)counter);
    gui_top_at(10, 1, "Interval: %lu", (unsigned long)tok->interval);

    gui_top_at(12, 1, "UP/DOWN: select");
    gui_top_at(13, 1, "A: reload");
    gui_top_at(14, 1, "X:delete selected  Y:scan QR");
    clear_top_row(18);
    if (app->status_msg[0] != '\0')
      gui_top_at(18, 1, "%s", app->status_msg);
    gui_top_at(22, 13, "%06lu", (unsigned long)code);
  }

  consoleSelect(&app->bottom_console);
  printf("\x1b[2J");

  if (count > 0) {
    const token_t *tok;
    uint32_t code;
    uint32_t remain;
    int64_t elapsed;

    if (selected >= count)
      selected = 0;

    tok = &tokens[selected];
    code = compute_totp(tok, now);
    elapsed = (int64_t)now - tok->t0;

    if (elapsed < 0)
      remain = tok->interval;
    else
      remain = tok->interval - ((uint32_t)elapsed % tok->interval);

    gui_bottom_at(1, 1, "Refresh: %lus", (unsigned long)remain);

    list_top_row = 1 + top_info_rows + top_padding_rows;
    list_bottom_row = code_row - gap_before_code - 1;
    available_rows = list_bottom_row - list_top_row + 1;
    if (available_rows < 1)
      available_rows = 1;

    for (i = 0; i < count; i++) {
      size_t l = strlen(tokens[i].label);
      size_t lines = (l + (size_t)label_cols - 1) / (size_t)label_cols;
      if (lines == 0)
        lines = 1;
      row_cost[i] = lines;
    }

    start = selected;
    end = selected + 1;
    used_rows = row_cost[selected];

    for (i = 1; i < count; i++) {
      size_t up = (selected >= i) ? (selected - i) : count;
      size_t down = selected + i;
      int added = 0;

      if ((up < count) && (up < start) &&
          ((int)(used_rows + row_cost[up] + service_gap_rows) <=
           available_rows)) {
        start = up;
        used_rows += row_cost[up] + service_gap_rows;
        added = 1;
      }

      if ((down < count) && (down >= end) &&
          ((int)(used_rows + row_cost[down] + service_gap_rows) <=
           available_rows)) {
        end = down + 1;
        used_rows += row_cost[down] + service_gap_rows;
        added = 1;
      }

      if (!added && (up >= count) && (down >= count))
        break;
      if (!added && ((int)used_rows >= available_rows))
        break;
    }

    row_cursor = list_top_row;
    for (i = start; i < end; i++) {
      size_t line_idx;
      size_t label_len = strlen(tokens[i].label);

      for (line_idx = 0; line_idx < row_cost[i] && row_cursor <= list_bottom_row;
           line_idx++, row_cursor++) {
        size_t off = line_idx * (size_t)label_cols;
        size_t rem = (off < label_len) ? (label_len - off) : 0;
        size_t chunk = (rem > (size_t)label_cols) ? (size_t)label_cols : rem;

        gui_clear_bottom_row(row_cursor);
        if (line_idx == 0) {
          gui_bottom_at(row_cursor, 1, "%c%.*s", (i == selected) ? '>' : ' ',
                        (int)chunk, tokens[i].label + off);
        } else {
          gui_bottom_at(row_cursor, 1, " %.*s", (int)chunk,
                        tokens[i].label + off);
        }
      }

      if ((i + 1 < end) && (service_gap_rows > 0)) {
        int g;
        for (g = 0; (g < service_gap_rows) && (row_cursor <= list_bottom_row);
             g++, row_cursor++) {
          gui_clear_bottom_row(row_cursor);
        }
      }
    }

    while (row_cursor <= list_bottom_row) {
      gui_clear_bottom_row(row_cursor);
      row_cursor++;
    }

    gui_bottom_at(22, 13, "%06lu", (unsigned long)code);
  } else {
    gui_bottom_at(1, 1, "No tokens loaded");
  }
}
