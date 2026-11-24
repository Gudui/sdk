# Pinned external v0.45 SDK. No test, send, or deploy target.
ifndef PS5_PAYLOAD_SDK
$(error Set PS5_PAYLOAD_SDK to the SHA-verified PS5 Payload SDK v0.45 release directory)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
OUTDIR ?= build-e10a4s-v045
ELF := $(OUTDIR)/fw550_e10a4_startup_v045.elf
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror
.PHONY: all
all: $(ELF)
$(ELF): main.c
	@mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ main.c
