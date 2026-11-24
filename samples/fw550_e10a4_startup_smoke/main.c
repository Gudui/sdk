/* E10A.4S: minimally instrumented user-space startup baseline.
 * LINK ONLY with pinned v0.45 SDK known-good PadBridge environment.
 * No diagnostic kernel reads, Bluetooth or firmware text modification.
 * SDK CRT itself performs kernel-data reads / process privilege writes
 * BEFORE main(). This is a startup contract test, NOT a globally read-only ELF.
 */
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/klog.h>

#define PS5_FW550_RAW UINT32_C(0x05500000)

int main(void) {
  uint32_t fw;
  klog_puts("E10A4S MAIN_ENTER baseline=sdk_v045");
  fw=kernel_get_fw_version();
  klog_printf("E10A4S FIRMWARE raw=0x%x expected=0x5500000\n",fw);
  if((fw & UINT32_C(0xffff0000)) != PS5_FW550_RAW) {
    klog_puts("E10A4S EXIT_FAIL reason=NOT_FW550");
    return 2;
  }
  klog_puts("E10A4S EXIT_OK status=0");
  return 0;
}
