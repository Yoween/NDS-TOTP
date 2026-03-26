/*
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2019-2025, Michael Santos <michael.santos@gmail.com>
 *  Copyright (c) 2015, David M. Syzdek <david@syzdek.net>
 *  All rights reserved.
 */

#include <fat.h>
#include <hmac/hmac.h>
#include <nds.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_TOKENS 32
#define MAX_LABEL_LEN 63
#define MAX_KEY_LEN 64
#define LINE_BUF_LEN 256

/*
 * Manual correction applied to time(NULL) before TOTP computation.
 * Example: if the DS runs +3600s ahead, set to -3600.
 */
#define TIME_CORRECTION_SECONDS -3600

static int g_time_correction_seconds = TIME_CORRECTION_SECONDS;

static PrintConsole g_top_console;
static PrintConsole g_bottom_console;

static const int8_t base32_vals[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    14, 11, 26, 27, 28, 29, 30, 31, 1,  -1, -1, -1, -1, 0,  -1, -1,
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

typedef struct token_s {
  char label[MAX_LABEL_LEN + 1];
  uint8_t key[MAX_KEY_LEN];
  size_t key_len;
  uint32_t interval;
  int64_t t0;
} token_t;



static int parse_time_correction_line(const char *line, int *value) {
  const char *eq;
  long parsed;

  eq = strchr(line, '=');
  if (eq == NULL)
    return 0;

  if ((strncmp(line, "time_correction", (size_t)(eq - line)) != 0) &&
      (strncmp(line, "TIME_CORRECTION_SECONDS", (size_t)(eq - line)) != 0))
    return 0;

  parsed = strtol(eq + 1, NULL, 0);
  if (parsed < -86400)
    parsed = -86400;
  if (parsed > 86400)
    parsed = 86400;
  *value = (int)parsed;
  return 1;
}



static char *trim(char *s) {
  char *end;

  while ((*s == ' ') || (*s == '\t') || (*s == '\r') || (*s == '\n'))
    s++;

  if (*s == '\0')
    return s;

  end = s + strlen(s) - 1;
  while ((end > s) && ((*end == ' ') || (*end == '\t') || (*end == '\r') ||
                       (*end == '\n')))
    end--;
  end[1] = '\0';

  return s;
}

static int base32_decode(const char *in, uint8_t *out, size_t out_cap,
                         size_t *out_len) {
  size_t len;
  size_t pos;
  size_t keylen;

  len = strlen(in);
  if (len == 0)
    return -1;

  if (((len & 0xF) != 0) && ((len & 0xF) != 8))
    return -1;

  for (pos = 0; pos < len; pos++) {
    uint8_t ch = (uint8_t)in[pos];

    if (base32_vals[ch] == -1)
      return -1;

    if (ch == '=') {
      if (((pos & 0xF) == 0) || ((pos & 0xF) == 8))
        return -1;
      if ((len - pos) > 6)
        return -1;

      switch (pos % 8) {
      case 2:
      case 4:
      case 5:
      case 7:
        break;
      default:
        return -1;
      }

      for (; pos < len; pos++) {
        if (in[pos] != '=')
          return -1;
      }
      break;
    }
  }

  keylen = 0;
  for (pos = 0; pos <= (len - 8); pos += 8) {
    if ((keylen + 5) > out_cap)
      return -1;

    out[keylen + 0] = (base32_vals[(uint8_t)in[pos + 0]] << 3) & 0xF8;
    out[keylen + 0] |= (base32_vals[(uint8_t)in[pos + 1]] >> 2) & 0x07;
    if (in[pos + 2] == '=') {
      keylen += 1;
      break;
    }

    out[keylen + 1] = (base32_vals[(uint8_t)in[pos + 1]] << 6) & 0xC0;
    out[keylen + 1] |= (base32_vals[(uint8_t)in[pos + 2]] << 1) & 0x3E;
    out[keylen + 1] |= (base32_vals[(uint8_t)in[pos + 3]] >> 4) & 0x01;
    if (in[pos + 4] == '=') {
      keylen += 2;
      break;
    }

    out[keylen + 2] = (base32_vals[(uint8_t)in[pos + 3]] << 4) & 0xF0;
    out[keylen + 2] |= (base32_vals[(uint8_t)in[pos + 4]] >> 1) & 0x0F;
    if (in[pos + 5] == '=') {
      keylen += 3;
      break;
    }

    out[keylen + 3] = (base32_vals[(uint8_t)in[pos + 4]] << 7) & 0x80;
    out[keylen + 3] |= (base32_vals[(uint8_t)in[pos + 5]] << 2) & 0x7C;
    out[keylen + 3] |= (base32_vals[(uint8_t)in[pos + 6]] >> 3) & 0x03;
    if (in[pos + 7] == '=') {
      keylen += 4;
      break;
    }

    out[keylen + 4] = (base32_vals[(uint8_t)in[pos + 6]] << 5) & 0xE0;
    out[keylen + 4] |= (base32_vals[(uint8_t)in[pos + 7]] >> 0) & 0x1F;
    keylen += 5;
  }

  *out_len = keylen;
  return 0;
}

static uint32_t compute_totp(const token_t *token, time_t now) {
  uint64_t counter;
  uint8_t msg[8] = {0};
  uint8_t hmac_result[20] = {0};
  size_t hmac_len;
  uint64_t offset;
  uint32_t bin_code;
  int64_t elapsed;

  if (token->interval == 0)
    return 0;

  elapsed = (int64_t)now - token->t0;
  if (elapsed < 0)
    return 0;

  counter = (uint64_t)(elapsed / (int64_t)token->interval);

  msg[0] = (uint8_t)((counter >> 56) & 0xFF);
  msg[1] = (uint8_t)((counter >> 48) & 0xFF);
  msg[2] = (uint8_t)((counter >> 40) & 0xFF);
  msg[3] = (uint8_t)((counter >> 32) & 0xFF);
  msg[4] = (uint8_t)((counter >> 24) & 0xFF);
  msg[5] = (uint8_t)((counter >> 16) & 0xFF);
  msg[6] = (uint8_t)((counter >> 8) & 0xFF);
  msg[7] = (uint8_t)(counter & 0xFF);

  hmac_len = sizeof(hmac_result);
  hmac_sha1(token->key, token->key_len, msg, sizeof(msg), hmac_result, &hmac_len);

  offset = hmac_result[19] & 0x0F;
  bin_code = (hmac_result[offset] & 0x7F) << 24 |
             (hmac_result[offset + 1] & 0xFF) << 16 |
             (hmac_result[offset + 2] & 0xFF) << 8 |
             (hmac_result[offset + 3] & 0xFF);

  return bin_code % 1000000;
}

static int load_tokens(token_t *tokens, size_t *count, const char **loaded_path,
                       int *time_correction_seconds) {
  static const char *paths[] = {
      "sd:/totp/tokens.txt",
      "fat:/totp/tokens.txt",
      "/totp/tokens.txt",
  };

  FILE *fp = NULL;
  char line[LINE_BUF_LEN];
  size_t line_no;
  size_t idx;

  *count = 0;
  *loaded_path = NULL;

  for (idx = 0; idx < (sizeof(paths) / sizeof(paths[0])); idx++) {
    fp = fopen(paths[idx], "r");
    if (fp != NULL) {
      *loaded_path = paths[idx];
      break;
    }
  }

  if (fp == NULL)
    return -1;

  line_no = 0;
  while (fgets(line, sizeof(line), fp) != NULL) {
    char *cur;
    char *label;
    char *secret;
    char *interval_s;
    char *start_s;
    token_t token;
    unsigned long interval_ul;

    line_no++;
    cur = trim(line);

    if ((cur[0] == '\0') || (cur[0] == '#'))
      continue;

    if (parse_time_correction_line(cur, time_correction_seconds))
      continue;

    label = trim(strtok(cur, "|"));
    secret = trim(strtok(NULL, "|"));
    interval_s = strtok(NULL, "|");
    start_s = strtok(NULL, "|");

    if ((label == NULL) || (secret == NULL))
      continue;

    if (strlen(label) > MAX_LABEL_LEN)
      continue;

    memset(&token, 0, sizeof(token));
    strncpy(token.label, label, MAX_LABEL_LEN);
    token.interval = 30;
    token.t0 = 0;

    if (interval_s != NULL) {
      interval_s = trim(interval_s);
      interval_ul = strtoul(interval_s, NULL, 0);
      if (interval_ul > 0)
        token.interval = (uint32_t)interval_ul;
    }

    if (start_s != NULL) {
      start_s = trim(start_s);
      token.t0 = strtoll(start_s, NULL, 0);
    }

    if (base32_decode(secret, token.key, sizeof(token.key), &token.key_len) < 0)
      continue;

    if (*count >= MAX_TOKENS)
      break;

    tokens[*count] = token;
    (*count)++;
  }

  fclose(fp);
  return 0;
}

static void draw_ui(const token_t *tokens, size_t count, size_t selected,
                    const char *loaded_path __attribute__((unused)),
                    int time_correction_seconds) {
  size_t i;
  size_t start;
  size_t end;
  time_t raw_now;
  time_t now;
  int64_t corrected_now;

  raw_now = time(NULL);
  corrected_now = (int64_t)raw_now + (int64_t)time_correction_seconds;
  now = (time_t)corrected_now;

  /* TOP SCREEN: Detailed info */
  consoleSelect(&g_top_console);
  iprintf("\x1b[2J\x1b[H");
  iprintf("DSi TOTP\n");
  iprintf("Raw:  %ld\n", (long)raw_now);
  iprintf("Adj:  %ld\n", (long)now);
  iprintf("Corr: %+d\n\n", time_correction_seconds);

  if (count == 0) {
    iprintf("No tokens loaded\n");
  } else {
    if (selected >= count)
      selected = 0;

    const token_t *tok = &tokens[selected];
    uint32_t code = compute_totp(tok, now);
    uint32_t remain;
    int64_t elapsed = (int64_t)now - tok->t0;
    uint64_t counter;

    if (elapsed < 0) {
      remain = tok->interval;
      counter = 0;
    } else {
      remain = tok->interval - ((uint32_t)elapsed % tok->interval);
      counter = (uint64_t)(elapsed / (int64_t)tok->interval);
    }

    iprintf("Code:  %06lu\n", (unsigned long)code);
    iprintf("Refresh: %lus\n", (unsigned long)remain);
    iprintf("Counter: %llu\n", (unsigned long long)counter);
    iprintf("Interval: %lu\n\n", (unsigned long)tok->interval);

    iprintf("UP/DOWN: select\n");
    iprintf("A: reload\n");
  }

  /* BOTTOM SCREEN: Info at top, selection in middle, code at bottom */
  consoleSelect(&g_bottom_console);
  printf("\x1b[2J");
  
  if (count > 0) {
    if (selected >= count)
      selected = 0;

    const token_t *tok = &tokens[selected];
    uint32_t code = compute_totp(tok, now);
    uint32_t remain;
    int64_t elapsed = (int64_t)now - tok->t0;

    if (elapsed < 0) {
      remain = tok->interval;
    } else {
      remain = tok->interval - ((uint32_t)elapsed % tok->interval);
    }

    /* Info at top */
    printf("\x1b[1;1HRaw: %ld Adj: %ld", (long)raw_now, (long)now);
    printf("\x1b[2;1HRefresh: %lus", (unsigned long)remain);

    /* Token selection in middle (always 5 rows, scroll around selection) */
    if (count <= 5) {
      start = 0;
    } else if (selected < 2) {
      start = 0;
    } else if (selected > (count - 3)) {
      start = count - 5;
    } else {
      start = selected - 2;
    }
    end = start + 5;

    for (i = start; i < end; i++) {
      int row = 8 + (int)(i - start);
      printf("\x1b[%d;1H", row);
      if (i < count) {
        printf("%c%-30.30s", i == selected ? '>' : ' ', tokens[i].label);
      } else {
        printf("                                ");
      }
    }

    /* Code centered with a bit of bottom padding */
    printf("\x1b[22;14H%06lu", (unsigned long)code);
  } else {
    printf("\x1b[1;1HNo tokens loaded");
  }
}

int main(void) {
  token_t tokens[MAX_TOKENS];
  size_t token_count;
  size_t selected;
  const char *loaded_path;
  time_t last_second;

  videoSetMode(MODE_0_2D);
  videoSetModeSub(MODE_0_2D);
  vramSetBankA(VRAM_A_MAIN_BG);
  vramSetBankC(VRAM_C_SUB_BG);

  consoleInit(&g_top_console, 0, BgType_Text4bpp, BgSize_T_256x256, 31, 0, true,
              true);
  consoleInit(&g_bottom_console, 0, BgType_Text4bpp, BgSize_T_256x256, 31, 0,
              false, true);
  consoleSelect(&g_bottom_console);

  printf("Initializing SD...\n");
  if (!fatInitDefault()) {
    iprintf("SD init failed\n");
    for (;;) {
      swiWaitForVBlank();
    }
  }

  printf("Current time: %ld\n", (long)time(NULL));
  printf("If this is 0 or too old,\n");
  printf("set DS clock in settings\n\n");

  token_count = 0;
  selected = 0;
  loaded_path = NULL;
  (void)load_tokens(tokens, &token_count, &loaded_path, &g_time_correction_seconds);

  keysSetRepeat(20, 6);
  last_second = (time_t)-1;

  while (1) {
    scanKeys();

    {
      int pressed = keysDown();
      if (pressed & KEY_START)
        exit(0);
#ifdef KEY_POWER
      if (pressed & KEY_POWER)
        exit(0);
#endif
    }

    {
      int down = keysDownRepeat();
      if (down & KEY_UP) {
        if (token_count > 0)
          selected = (selected == 0) ? (token_count - 1) : (selected - 1);
      }
      if (down & KEY_DOWN) {
        if (token_count > 0)
          selected = (selected + 1) % token_count;
      }
      if (down & KEY_A) {
        (void)load_tokens(tokens, &token_count, &loaded_path,
                          &g_time_correction_seconds);
        if (selected >= token_count)
          selected = 0;
      }
      if ((down & KEY_R) || (down & KEY_L)) {
        /* Reset/reload on L or R */
        (void)load_tokens(tokens, &token_count, &loaded_path,
                          &g_time_correction_seconds);
        if (selected >= token_count)
          selected = 0;
      }
    }

    {
      time_t now = time(NULL);
      if (now != last_second) {
        draw_ui(tokens, token_count, selected, loaded_path,
                g_time_correction_seconds);
        last_second = now;
      }
    }

    swiWaitForVBlank();
  }
}
