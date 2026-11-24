# E10A.4P: unique read-disabled preflight binary; NO deploy or launch targets.
ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK must be a separately built additive v0.45 SDK)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
OUTDIR ?= build-e10a4p-v045
ELF := $(OUTDIR)/fw550_e10a4P_read_disabled_additive_v045.elf
CFLAGS := -std=c11 -O1 -Wall -Wextra -Werror -ffreestanding -fno-builtin
.PHONY: all
all: $(ELF)
$(ELF): main.c ../fw550_e10a4_capture/fw550_read_contract.c ../fw550_e10a4_capture/fw550_read_contract.h ../fw550_e10a4_capture/fw550_windows_generated.h
	@mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ main.c ../fw550_e10a4_capture/fw550_read_contract.c
