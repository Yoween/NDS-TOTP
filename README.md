# NDS-TOTP

A TOTP (Time-Based One-Time Password) authenticator application for the Nintendo DS, ported from Simple C TOTP : https://github.com/msantos/totp.c.

## Features

- **Configurable Time Correction**: Handle DS clock drift with adjustable time offset
- **SD Card Support**: Load tokens from `totp/tokens.txt` on your SD card
- **Quick Exit**: Press START button to return to the menu

## Hardware Requirements

- Nintendo DS / DSi with homebrew loader
- SD card with homebrew capability
- devkitARM toolchain (for building)

## Building

```bash
make
```

This generates `nds-totp.nds` ready for deployment.

## Installation

1. Copy `nds-totp.nds` to your DS
2. Create a `totp/` folder on your SD card (or place tokens.txt in an existing one)
3. Add your tokens to `totp/tokens.txt`

## Configuration

### Token Format

Create a file `totp/tokens.txt` with the following format (pipe-delimited):

```txt
label|base32_secret|interval_seconds|unix_epoch_t0
```

#### Example

```txt
GitHub|JBSWY3DPEBLW64TMMQ======|30|0
MyEmail|OBWGC2LOFVZXG53POJZXG53POJZXG53P|30|0
```

### Time Correction

If your DS runs ahead or behind the correct time, add this line to `tokens.txt`:

```txt
time_correction=-3600
```

This offsets the system clock by the specified number of seconds. Common values:

- `-3600` for 1 hour ahead
- `+3600` for 1 hour behind

## Controls

| Button | Action |
| ------ | ------ |
| UP / DOWN | Navigate service list |
| A | Reload tokens from SD card |
| L / R | Reload tokens from SD card |
| START | Return to menu |

## Display Layout

### Top Screen

- System time (raw and adjusted)
- Time correction offset applied
- Currently selected token details (code, refresh countdown, counter, interval)
- Quick help (UP/DOWN to select, A to reload)

### Bottom Screen

- **Top**: System time info
- **Middle**: Scrollable list of 5 services at a time
- **Bottom**: Centered 6-digit OTP code

## Technical Details

### Cryptographic Stack

- **HMAC-SHA1**: Custom implementation using Steve Reid's public domain SHA-1
- **Base32 Decoding**: RFC 4648 compliant with proper padding validation
- **Counter Mode**: RFC 6238 time-step counter: `counter = (now - t0) / interval`

### NDS-Specific

- Dual-screen console via libnds
- SD card access via libfat
- Cross-compiled for ARM9 with devkitARM

## Troubleshooting

**No tokens appear**: Ensure `tokens.txt` is placed at `/totp/tokens.txt` on your SD card and the file format is correct.

**Wrong codes generated**: Check your time correction offset. Use the top screen to see the raw and adjusted system times.

**Time stuck at 0**: Set the DS clock in system settings before launching the app.

## License

This port combines:

- Original TOTP algorithm concept and base code
- Steve Reid's public domain SHA-1 implementation
- libnds and devkitARM toolchain

See individual source files for detailed attribution.

## Author

Ported by Tristan LAROCHE, with the help of GitHub Copilot (2026)

---

**Note**: This application is for personal use only. Always keep your OTP secrets safe and never share your `tokens.txt` file.
