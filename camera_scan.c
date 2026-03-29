/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "camera_scan.h"

#include "gui.h"

#include <camera.h>
#include <quirc.h>
#include <stdio.h>
#include <string.h>

#ifndef QR_DETECT_ONLY
#define QR_DETECT_ONLY 0
#endif

/*
 * Camera capture pipeline:
 * - preview frame in RGB555
 * - grayscale conversion for quirc
 * - decode loop with stall recovery and camera switch support
 */

static struct quirc_code g_qr_code;
static struct quirc_data g_qr_data;

static void rgb555_to_gray8(const uint16_t *src, uint8_t *dst, size_t count) {
  size_t i;
  for (i = 0; i < count; i++) {
    uint16_t px = src[i];
    uint8_t r = (uint8_t)(px & 0x1F);
    uint8_t g = (uint8_t)((px >> 5) & 0x1F);
    uint8_t b = (uint8_t)((px >> 10) & 0x1F);
    uint8_t r8 = (uint8_t)(r << 3);
    uint8_t g8 = (uint8_t)(g << 3);
    uint8_t b8 = (uint8_t)(b << 3);
    dst[i] = (uint8_t)(((uint16_t)r8 * 30 + (uint16_t)g8 * 59 +
                        (uint16_t)b8 * 11) /
                       100);
  }
}

static void camera_transfer_stop_sync(void) {
  int guard;

  cameraTransferStop();
  for (guard = 0; guard < 400 && cameraTransferActive(); guard++)
    swiWaitForVBlank();
}

int scan_otpauth_qr(app_state_t *app, char *out_uri, size_t out_cap, char *err,
                    size_t err_cap) {
  struct quirc *qr;
  int bg;
  uint16_t *frame;
  Camera active_cam = CAM_OUTER;
  int frame_idx;
  int stall_frames = 0;
  int recoveries = 0;
  int decode_tick = 0;

  if (out_cap == 0)
    return -1;

  out_uri[0] = '\0';
  err[0] = '\0';

  if (!isDSiMode()) {
    snprintf(err, err_cap, "QR camera: DSi requis");
    return -1;
  }

  qr = quirc_new();
  if (qr == NULL) {
    snprintf(err, err_cap, "QR init memoire echoue");
    return -1;
  }

  if (quirc_resize(qr, QR_FRAME_W, QR_FRAME_H) < 0) {
    quirc_destroy(qr);
    snprintf(err, err_cap, "QR resize echoue");
    return -1;
  }

  videoSetMode(MODE_5_2D);
  vramSetBankA(VRAM_A_MAIN_BG_0x06040000);
  bg = bgInit(2, BgType_Bmp16, BgSize_B16_256x256, 16, 0);
  frame = (uint16_t *)bgGetGfxPtr(bg);
  memset(frame, 0, (size_t)QR_FRAME_W * (size_t)QR_FRAME_H * sizeof(uint16_t));

  pxiWaitRemote(PXI_CAMERA);
  if (!cameraInit() || !cameraActivate(active_cam)) {
    quirc_destroy(qr);
    gui_restore_text_consoles(app);
    snprintf(err, err_cap, "Camera init/activate failed");
    return -1;
  }

  consoleSelect(&app->bottom_console);
  printf("\x1b[2J");
  gui_bottom_at(1, 1, "Scan QR...");
  gui_bottom_at(2, 1, "B: switch cam");
  gui_bottom_at(3, 1, "START: cancel");
  gui_bottom_at(4, 1, "State: init capture");

  cameraTransferStart(frame, CAPTURE_MODE_PREVIEW);

  /* Bounded loop avoids endless camera lockups and keeps cancel responsive. */
  for (frame_idx = 0; frame_idx < 1200; frame_idx++) {
    int keys;
    int w;
    int h;
    int n;
#if !QR_DETECT_ONLY
    int i;
#endif
    uint8_t *img;

    scanKeys();
    keys = keysDown();
    if (keys & KEY_START) {
      snprintf(err, err_cap, "Scan cancelled");
      camera_transfer_stop_sync();
      cameraDeactivate(active_cam);
      quirc_destroy(qr);
      gui_restore_text_consoles(app);
      return -2;
    }

    if (keys & KEY_B) {
      Camera next = (active_cam == CAM_OUTER) ? CAM_INNER : CAM_OUTER;
      camera_transfer_stop_sync();
      if (cameraActivate(next))
        active_cam = next;
      cameraTransferStart(frame, CAPTURE_MODE_PREVIEW);
      stall_frames = 0;
      recoveries = 0;
      decode_tick = 0;
      gui_bottom_at(4, 1, "State: switch camera   ");
      continue;
    }

    if (cameraTransferActive()) {
      stall_frames++;
      if ((frame_idx % 20) == 0)
        gui_bottom_at(4, 1, "State: capturing... %4d", frame_idx);

      if (stall_frames > 300) {
        recoveries++;
        gui_bottom_at(4, 1, "State: recovery %d     ", recoveries);
        camera_transfer_stop_sync();
        if (recoveries > 8) {
          cameraDeactivate(active_cam);
          quirc_destroy(qr);
          gui_restore_text_consoles(app);
          snprintf(err, err_cap, "Camera stalled (no frame)");
          return -1;
        }
        cameraTransferStart(frame, CAPTURE_MODE_PREVIEW);
        stall_frames = 0;
      }
      swiWaitForVBlank();
      continue;
    }

    stall_frames = 0;
    recoveries = 0;
    decode_tick++;
    if ((frame_idx % 20) == 0)
      gui_bottom_at(4, 1, "State: decode...  %4d", frame_idx);

    if ((decode_tick & 1) != 0) {
      img = quirc_begin(qr, &w, &h);
      if ((w == QR_FRAME_W) && (h == QR_FRAME_H)) {
        rgb555_to_gray8(frame, img, (size_t)QR_FRAME_W * (size_t)QR_FRAME_H);
      }
      quirc_end(qr);

      n = quirc_count(qr);
      if (n > 0) {
        gui_clear_bottom_row(5);
        gui_clear_bottom_row(6);
        gui_bottom_at(5, 1, "QR detecte (%d)", n);
        gui_bottom_at(6, 1, "Traitement...");
#if QR_DETECT_ONLY
        camera_transfer_stop_sync();
        cameraDeactivate(active_cam);
        quirc_destroy(qr);
        gui_restore_text_consoles(app);
        snprintf(err, err_cap, "QR detecte (test)");
        return -3;
#else
        camera_transfer_stop_sync();
        cameraDeactivate(active_cam);

        if (n > 1)
          n = 1;

        for (i = 0; i < n; i++) {
          quirc_decode_error_t dec;
          size_t payload_len;

          quirc_extract(qr, i, &g_qr_code);

          dec = quirc_decode(&g_qr_code, &g_qr_data);
          if (dec != QUIRC_SUCCESS) {
            quirc_flip(&g_qr_code);
            dec = quirc_decode(&g_qr_code, &g_qr_data);
          }
          if (dec != QUIRC_SUCCESS)
            continue;

          payload_len = (size_t)g_qr_data.payload_len;
          if (payload_len >= out_cap)
            payload_len = out_cap - 1;
          memcpy(out_uri, g_qr_data.payload, payload_len);
          out_uri[payload_len] = '\0';

          if (strncmp(out_uri, "otpauth://totp/", 15) == 0) {
            gui_clear_bottom_row(5);
            gui_clear_bottom_row(6);
            gui_bottom_at(5, 1, "QR detected and read");
            gui_bottom_at(6, 1, "otpauth valid, import...");
            quirc_destroy(qr);
            gui_restore_text_consoles(app);
            return 0;
          }
        }

        quirc_destroy(qr);
        gui_restore_text_consoles(app);
        snprintf(err, err_cap,
                 "QR detected but non-otpauth\n  Please try scanning again");
        return -1;
#endif
      }
    }

    cameraTransferStart(frame, CAPTURE_MODE_PREVIEW);

    swiWaitForVBlank();
  }

  camera_transfer_stop_sync();
  cameraDeactivate(active_cam);
  quirc_destroy(qr);
  gui_restore_text_consoles(app);
  snprintf(err, err_cap, "No otpauth QR code found");
  return -1;
}
