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

SRCS := totp.c hmac/hmac_sha1.c sha/sha1.c
OBJS := $(SRCS:.c=.o)

INCLUDES := -I. -Ihmac -Isha -I$(LIBNDS)/include -I$(CALICO)/include -I$(DEVKITPRO)/portlibs/nds/include
ARCH := -march=armv5te -mtune=arm946e-s -mthumb
CFLAGS := -O2 -Wall -Wextra $(ARCH) -ffunction-sections -fdata-sections -DARM9 -D__NDS__ $(INCLUDES)
LDFLAGS := -specs=$(CALICO)/share/ds9.specs $(ARCH) -L$(CALICO)/lib -L$(LIBNDS)/lib -L$(DEVKITPRO)/portlibs/nds/lib
LIBS := -lnds9 -lfilesystem -lfat -lcalico_ds9 -lm

.PHONY: all clean

all: $(NDS)

$(NDS): $(ELF)
	@echo "Creating NDS ROM..."
	@$(NDSTOOL) -c $@ -9 $< -7 $(ARM7_ELF) -b $(GAME_ICON) "NDS-TOTP;NDS-TOTP;NDS-TOTP"

$(ELF): $(OBJS)
	@echo "Linking $@..."
	@$(LD) $(LDFLAGS) $(OBJS) $(LIBS) -o $@
	@$(NM) -CSn $@ > $(notdir $*.lst)

%.o: %.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "Cleaning..."
	@rm -f $(OBJS) $(ELF) $(NDS) $(patsubst %.o,%.lst,$(ELF))

