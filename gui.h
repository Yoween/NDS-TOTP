#ifndef NDS_TOTP_GUI_H
#define NDS_TOTP_GUI_H

#include "app.h"

void gui_init_text_consoles(app_state_t *app);
void gui_restore_text_consoles(app_state_t *app);
void gui_draw_ui(app_state_t *app, const token_t *tokens, size_t count,
                 size_t selected);
void gui_clear_status_row(void);

void gui_top_at(int row, int col, const char *fmt, ...);
void gui_bottom_at(int row, int col, const char *fmt, ...);
void gui_clear_bottom_row(int row);

int gui_unlock_and_load_tokens(app_state_t *app, token_t *tokens,
                               size_t *count, const char **loaded_path);

#endif
