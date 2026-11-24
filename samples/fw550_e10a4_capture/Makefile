# E10A.4 checked FW550 original windows — isolated output, no deploy rule.
ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK must point to THIS v0.45-derived SDK install)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
OUTDIR ?= build-fw550-v045-checked
ELF := $(OUTDIR)/fw550_e10a4_checked_v045.elf
CFLAGS := -std=c11 -O1 -Wall -Wextra -Werror -ffreestanding -fno-builtin
.PHONY: all
all: $(ELF)
$(ELF): main.c fw550_read_contract.c fw550_read_contract.h fw550_windows_generated.h
	@mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ main.c fw550_read_contract.c
