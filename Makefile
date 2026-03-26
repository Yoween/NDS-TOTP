#---------------------------------------------------------------------------------
.SUFFIXES:
#---------------------------------------------------------------------------------

DEVKITPRO ?= /opt/devkitpro
DEVKITARM ?= $(DEVKITPRO)/devkitARM

PREFIX := $(DEVKITARM)/bin/arm-none-eabi-
CC := $(PREFIX)gcc
AR := $(PREFIX)ar
LD := $(PREFIX)gcc
NM := $(PREFIX)nm
OBJCOPY := $(PREFIX)objcopy

NDSTOOL := $(DEVKITPRO)/tools/bin/ndstool
CALICO := $(DEVKITPRO)/calico
LIBNDS := $(DEVKITPRO)/libnds
ARM7_ELF := $(CALICO)/bin/ds7_maine.elf
GAME_ICON := $(CALICO)/share/nds-icon.bmp

TARGET := nds-totp
ELF := $(TARGET).elf
NDS := $(TARGET).nds
LST := $(TARGET).lst
HOSTCC := gcc
PACKER := tools/totp-pack
ARM7_APP_ELF := $(TARGET)-arm7.elf

SRCS := totp.c hmac/hmac_sha1.c sha/sha1.c \
	third_party/dsi-camera/arm9/source/camera.c \
	third_party/quirc/lib/quirc.c \
	third_party/quirc/lib/decode.c \
	third_party/quirc/lib/identify.c \
	third_party/quirc/lib/version_db.c
OBJS := $(SRCS:.c=.o)

ARM7_SRCS := third_party/dsi-camera/arm7/source/main.c \
	third_party/dsi-camera/arm7/source/i2c_handler.c \
	third_party/dsi-camera/arm7/source/aptina.c \
	third_party/dsi-camera/arm7/source/aptina_i2c.c

INCLUDES := -I. -Ihmac -Isha -I$(LIBNDS)/include -I$(CALICO)/include -I$(DEVKITPRO)/portlibs/nds/include \
	-Ithird_party/dsi-camera/arm9/include -Ithird_party/dsi-camera/shared/include -Ithird_party/quirc/lib
ARCH := -march=armv5te -mtune=arm946e-s -mthumb
CFLAGS := -O2 -Wall -Wextra $(ARCH) -ffunction-sections -fdata-sections -DARM9 -D__NDS__ $(INCLUDES)
LDFLAGS := -specs=$(CALICO)/share/ds9.specs $(ARCH) -L$(CALICO)/lib -L$(LIBNDS)/lib -L$(DEVKITPRO)/portlibs/nds/lib
LIBS := -lnds9 -lfilesystem -lfat -lcalico_ds9 -lm

INCLUDES7 := -I. -I$(LIBNDS)/include -I$(CALICO)/include -I$(DEVKITPRO)/portlibs/nds/include \
	-Ithird_party/dsi-camera/arm7/include -Ithird_party/dsi-camera/shared/include
ARCH7 := -march=armv4t -mtune=arm7tdmi -mthumb
CFLAGS7 := -O2 -Wall -Wextra $(ARCH7) -ffunction-sections -fdata-sections -DARM7 -D__NDS__ $(INCLUDES7)
LDFLAGS7 := -specs=$(CALICO)/share/ds7.specs $(ARCH7) -L$(CALICO)/lib -L$(LIBNDS)/lib -L$(DEVKITPRO)/portlibs/nds/lib
LIBS7 := -lnds7 -lcalico_ds7 -lm

.PHONY: all clean packer

all: $(NDS)

packer: $(PACKER)

$(PACKER): tools/totp_pack.c hmac/hmac_sha1.c sha/sha1.c
	@echo "Building $@..."
	@$(HOSTCC) -O2 -Wall -Wextra -I. -Ihmac -Isha $^ -o $@

$(NDS): $(ELF) $(ARM7_APP_ELF)
	@echo "Creating NDS ROM..."
	@$(NDSTOOL) -c $@ -9 $(ELF) -7 $(ARM7_APP_ELF) -b $(GAME_ICON) "NDS-TOTP;NDS-TOTP;NDS-TOTP"

$(ARM7_APP_ELF): $(ARM7_SRCS)
	@echo "Linking $@..."
	@$(CC) $(CFLAGS7) $^ $(LDFLAGS7) $(LIBS7) -o $@

$(ELF): $(OBJS)
	@echo "Linking $@..."
	@$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o $@
	@$(NM) -CSn $@ > $(LST)

%.o: %.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning..."
	@rm -f $(OBJS) $(ELF) $(NDS) $(LST) $(PACKER) $(ARM7_APP_ELF)

