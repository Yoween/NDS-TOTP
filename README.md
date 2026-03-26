# NDS-TOTP

A TOTP authenticator for Nintendo DS/DSi with encrypted token storage and touchscreen 3x3 pattern unlock. Ported from [Simple C TOTP](https://github.com/msantos/totp.c).

## Version

- **V2** (current): encrypted vault + pattern unlock + on-device QR import from DSi camera.

## Features

- RFC 6238-compliant TOTP (6 digits).
- HMAC-SHA1 cryptography.
- Encrypted token vault in `/totp/tokens.bin`.
- 3x3 pattern lock screen on touchscreen before token display.
- Dual-screen UI:
  - Top: diagnostics and active token info.
  - Bottom: service list (5 visible) and large current code.
- `START` quick exit.
- QR import directly on DSi camera (`Y`).
- Safe delete flow in-app:
  - `X` arms deletion
  - `Y` confirms deletion
  - pressing `X` again cancels deletion

## Requirements

- Nintendo DS / DSi with homebrew loader.
- SD card.
- devkitARM + libnds for DS build.
- host `gcc` for the token packer tool.

## Build

```bash
make
make packer
```

Outputs:

- `nds-totp.nds` (DS application)
- `tools/totp-pack` (host utility)

## Create encrypted token file

Commands:

```bash
tools/totp-pack add  /path/to/tokens.bin <pattern> <label> <base32_secret> [interval] [t0]
tools/totp-pack set  /path/to/tokens.bin <pattern> <label> <base32_secret> [interval] [t0]
tools/totp-pack del  /path/to/tokens.bin <pattern> <label> [--yes]
tools/totp-pack rename /path/to/tokens.bin <pattern> <old_label> <new_label>
tools/totp-pack list /path/to/tokens.bin <pattern>
```

Pattern rules:

- digits `1..9`
- no duplicates
- minimum length: 4

Mapping:

```text
1 2 3
4 5 6
7 8 9
```

Example:

```bash
tools/totp-pack add ./tokens.bin 14789 GitHub JBSWY3DPEBLW64TMMQ====== 30 0
tools/totp-pack add ./tokens.bin 14789 Email  OBWGC2LOFVZXG53POJZXG53POJZXG53P 30 0
tools/totp-pack rename ./tokens.bin 14789 Email WorkMail
tools/totp-pack set ./tokens.bin 14789 WorkMail  JBSWY3DPEHPK3PXP 30 0
tools/totp-pack del ./tokens.bin 14789 GitHub
tools/totp-pack list ./tokens.bin 14789
```

Important:

- One `tokens.bin` uses one unlock pattern for all entries.
- Mixing different patterns in the same file is rejected.
- `del` asks for confirmation (`Y` or `yes`). Use `--yes` to skip prompt.

## Install on SD

1. Copy `nds-totp.nds` to your DS launcher location.
2. Copy `tokens.bin` to `/totp/tokens.bin` on SD.
3. Launch app and draw the same pattern to unlock.

## Controls

- Touchscreen: Draw unlock pattern
- UP / DOWN: Navigate service list
- A: Reload encrypted tokens
- L / R: Reload encrypted tokens
- X: Arm deletion for selected entry
- Y: Confirm deletion (after X), otherwise scan `otpauth://...` from DSi camera
- START: Exit app

## Notes

- This V2 stores encrypted entries in `tokens.bin`.
- Tokens are decrypted in RAM only after successful unlock.
- Keep your pattern secret; anyone with SD + pattern can decrypt tokens.
- QR scan (`Y`) requires DSi mode and uses the built-in camera.

## Credits

- Original TOTP C project: Michael Santos — [msantos/totp.c](https://github.com/msantos/totp.c)
- QR decoding library: Daniel Beer — [dlbeer/quirc](https://github.com/dlbeer/quirc)
- DSi camera integration library: Epicpkmn11 — [Epicpkmn11/dsi-camera](https://github.com/Epicpkmn11/dsi-camera)
- SHA-1 / HMAC implementation used in this project is based on code credited in source headers to Michael Santos and David M. Syzdek.

## Troubleshooting

- No tokens: verify `/totp/tokens.bin` exists.
- Unlock fails: pattern must match exactly the one used with `totp-pack`.
- Wrong OTP time: adjust `TIME_CORRECTION_SECONDS` in [totp.c](totp.c).

## Changelog (V1 -> V2)

- Added encrypted vault workflow centered on `/totp/tokens.bin`.
- Added touchscreen 3x3 pattern unlock before token access.
- Added in-app QR import from DSi camera (`Y`).
- Added safer in-app deletion flow:
  - `X` arms deletion
  - `Y` confirms deletion
  - second `X` cancels deletion
- Added host management improvements in `totp-pack` (safer delete flow and clearer commands).
- Updated dual-screen UX and status messages.
- Integrated and credited third-party components for QR and DSi camera support.
