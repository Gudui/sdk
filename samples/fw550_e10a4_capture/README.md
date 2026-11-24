# E10A.4 — one-shot firmware 5.50 original text capture

**Offline compilation only until independent review and explicit PS5 authorization.**

## Boundary and provenance

- Fork: Gudui/sdk, branch `feat/fw550-checked-kernel-read`. Pin the exact commit SHA from `git rev-parse HEAD`.
- SDK CRT `crt/kernel.c` implements `kernel_copyout_exact()` alongside unchanged legacy `kernel_copyout()`; both call the shared `crt/kernel_copyout_core.h` state machine.
- Native user-space ELF builds against the same commit's installed SDK `crt1.o`, not the old deployed `kldload.elf`.
- `main.c` calls the original `fw550_capture_run()` contract and the original Stage B ten-window table (five sites + predecessors, 134 bytes). No kernel-native KLD or Sony text writes in diagnostic code.
- The CRT itself calls `__kernel_init`, which reads kernel data and establishes runtime state **before** `main`. Therefore ten windows means ten **diagnostic firmware-text** reads, not ten kernel memory operations overall.
- `kernel_copyout_exact()` is non-retrying and preserves actual signed syscall count. Failed/short reads are session-terminal at the consumer, **not** transactionally rolled back by the SDK.

## Checked-read API

`int32_t kernel_copyout_exact(intptr_t kaddr, void *dst, size_t len, kernel_copyout_exact_result_t *result)`.

`result` is zero-initialized for transfer and includes `stage`, `syscall_attempted`, signed `syscall_result`, positive `transferred` and captured `error_number`.
Success iff the two pipe setup operations and one `SYS_read` succeed AND the signed result equals `len`.
Stages: OK, INVALID, PIPE_FLAGS, PIPE_ADDRESS, SYS_READ, SHORT.
The legacy `kernel_copyout()` still accepts positive short reads as before, for ABI compatibility. The strict API never retries and does not translate a short read into success.
Underlying socket option / pipe metadata manipulation is a kernel write side effect, even though diagnostic code never writes Sony firmware text. The API is **not** reentrant, does not control a deadline, cannot guarantee fault containment, and does not clean or roll back the shared pipe after failure.

## Offline build (Ubuntu WSL, never invokes make test on existing loader)

```bash
set -euo pipefail
cd /mnt/c/Users/Hjemme-gamer/repos/padbridge-payload-sdk
git switch feat/fw550-checked-kernel-read
git pull --ff-only origin feat/fw550-checked-kernel-read
SDK_COMMIT=$(git rev-parse HEAD)
echo "SDK_COMMIT=$SDK_COMMIT"

make -C tests -f Makefile.checked-read test
python3 samples/fw550_e10a4_capture/tests/test_capture_validator.py
cc -std=c11 -O1 -g -Wall -Wextra -Werror \
    -o /tmp/fw550-contract-host-test \
    samples/fw550_e10a4_capture/tests/test_fw550_read_contract.c \
    samples/fw550_e10a4_capture/fw550_read_contract.c
/tmp/fw550-contract-host-test

DESTDIR="$HOME/ps5-payload-sdk-e10a4-$SDK_COMMIT"
make DESTDIR="$DESTDIR" LLVM_CONFIG=llvm-config-18 install
export PS5_PAYLOAD_SDK="$DESTDIR"
make -C samples/fw550_e10a4_capture all
ELF="samples/fw550_e10a4_capture/build-e10a4/fw550_e10a4_capture.elf"
sha256sum "$ELF" "$DESTDIR/target/lib/crt1.o"
llvm-nm-18 "$ELF" | grep kernel_copyout_exact
```

This builds into a separate SDK install path and the diagnostic's own output directory. It does **not** rebuild, delete or overwrite the preserved `padbridge-kldload-upstream/kldload.elf`.

For the independently built and audited GitHub Actions ELF, review the `FW550 E10A4 offline build (never deploy)` run at the pinned Git SHA and its downloadable `fw550-e10a4-diagnostic-review-only` artifact. Verify the ELF hash before any manual experiment.

## Manual console test procedure — NOT AUTOMATICALLY AUTHORIZED

1. Confirm the exact source/ELF SHA pair and independently review disassembly; preserve the original crashing E10A.3 artifacts.
2. Confirm active loader instances and pipe ownership; avoid concurrent use of the SDK read/write pipe. **The SDK has no exclusive-ownership proof or synchronization**, so this is a residual hazard, not a completed guarantee.
3. Ensure the console is stable, has a connected kernel log at TCP 3232, and has an explicit one-shot send marker / no-retry policy.
4. Send **only a separately approved PS5 user-space ELF** through the **user-space payload loader** (historically TCP **9021**); never send the ELF to the kernel-native KLD endpoint at 9022. Example command, run **only with separate human authorization**:
   `prospero-deploy -h "$PS5_HOST" -p 9021 "$ELF"`
5. Preserve the complete log, including START, every READ_BEGIN, READ_DONE, READ_BYTES, and final PASS or ABORT. Missing markers or a console panic are failures; never repeat automatically.
6. Offline log validation (never contacts PS5):
   `python3 samples/fw550_e10a4_capture/tools/verify_five_site_capture.py /path/to/preserved-console.log --write-json /path/to/capture.json`

## Non-negotiable residual hazards

- The pipe's kernel metadata is modified by `kernel_copyout_exact`, and an access violation may panic or hang the console before any status can be returned; a clean return does not imply fault isolation.
- The pipe state is persistent and shared with its owner. There is no per-read cleanup or enforceable timeout; logger and validator explicitly describe these limitations.
- `__kernel_init` performs additional kernel-data reads before main; these are neither part of the ten original windows nor covered by ten-window test receipts.
- Neither successful original-text read nor KLD-owned code modification demonstrates Sony firmware text write permission, safe multi-core publication, legitimate CFI entry or VU callback/peer lifecycle correctness.
- Even if all ten windows match, **the live installer remains a separate NO-GO decision** until publication and restoration ownership have evidence.
