# One-shot, offline-build-only PS5 user-space diagnostic.
# NEVER calls prospero-deploy; never touches the normal KLD loader build.
ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is undefined)
endif
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
OUTDIR ?= build-e10a4
ELF := $(OUTDIR)/fw550_e10a4_capture.elf
CFLAGS += -g -O1 -Wall -Wextra -Werror
.PHONY: all clean
all: $(ELF)
$(ELF): main.c
	mkdir -p $(OUTDIR)
	$(CC) $(CFLAGS) -o $@ main.c fw550_read_contract.c
clean:
	rm -rf $(OUTDIR)
