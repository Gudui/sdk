/* E10A.4P: read-disabled preflight for the exact D-based Stage B pipeline.
 *
 * Diagnostics only. No application-level firmware-text access or modification.
 * An intentional stub callback proves validation, first-window poisoning, and
 * the original %s-bearing READ_BEGIN formatting semantics; it then returns a
 * synthetic failed transfer so that the real contract immediately aborts.
 *
 * SDK CRT startup still performs its normal kernel-data reads/credential changes.
 * Never regard this payload as globally read-only.
 */
#include <stdint.h>
#include <stddef.h>
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include "../fw550_e10a4_capture/fw550_read_contract.h"

#define FW550_RAW_MASK UINT32_C(0xffff0000)
#define FW550_RAW_VERSION UINT32_C(0x05500000)
#define SYNTHETIC_READ_DISABLED_ERRNO 125

struct preflight_context {
  unsigned calls;
  unsigned good;
  uint64_t ktext;
};

static struct fw550_transfer_result read_disabled_once(
    uint64_t source, uint8_t *destination, size_t length, void *opaque) {
  struct preflight_context *ctx=(struct preflight_context *)opaque;
  const struct fw550_window *w=&fw550_stage_b_windows[0];
  struct fw550_transfer_result result={0};

  klog_puts("E10A4P CALLBACK_ENTER");
  ++ctx->calls;
  if(ctx->calls!=1 || !destination || source!=ctx->ktext+w->offset ||
     length!=w->length || w->length!=21 ||
     !w->site || !w->stage) {
    klog_puts("E10A4P ABORT reason=FIRST_WINDOW");
    result.read_errno=22;
    result.returned=-1;
    return result;
  }

  for(size_t i=0;i<length;++i) {
    if(destination[i]!=(uint8_t)(w->expected[i]^UINT8_C(0xff))) {
      klog_puts("E10A4P ABORT reason=POISON");
      result.read_errno=22;
      result.returned=-1;
      return result;
    }
  }
  klog_puts("E10A4P POISON_VALID");

  /* The single dynamic format is intentional: it isolates the precise
   * %s-bearing pre-read formatting path suspected in the failed D capture.
   * No firmware-text read or kernel_copyout_exact() follows this statement. */
  klog_puts("E10A4P FORMAT_BEGIN");
  klog_printf("E10A4P FORMAT_PROBE index=%u name=%s stage=%s va=%#lx requested=%lu\n",
              0u,w->site,w->stage,(unsigned long)source,
              (unsigned long)length);
  klog_puts("E10A4P FORMAT_RETURNED");

  ctx->good=1u;
  result.read_errno=SYNTHETIC_READ_DISABLED_ERRNO;
  result.returned=-1;
  return result;
}

int main(void) {
  klog_puts("E10A4P MAIN_ENTER read_disabled=1");
  unsigned firmware=kernel_get_fw_version();
  uint64_t text=(uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t data=(uint64_t)KERNEL_ADDRESS_DATA_BASE;
  struct preflight_context ctx={0,0,text};
  struct fw550_capture_report report;
  enum fw550_capture_status rc;
  unsigned total=0;
  klog_puts("E10A4P LAYOUT_OBSERVED");
  if((firmware&FW550_RAW_MASK)!=FW550_RAW_VERSION ||
     text<UINT64_C(0xffff800000000000) ||
     data<text || data-text!=FW550_TEXT_LENGTH) {
    klog_puts("E10A4P ABORT reason=FIRMWARE_OR_LAYOUT");
    return 2;
  }
  klog_puts("E10A4P LAYOUT_VALID");
  for(unsigned i=0;i<FW550_WINDOW_COUNT;++i)
    total+=fw550_stage_b_windows[i].length;
  if(total!=134u) {
    klog_puts("E10A4P ABORT reason=TOTAL_NOT_134");
    return 3;
  }
  klog_puts("E10A4P TEN_WINDOWS_134");
  klog_puts("E10A4P CONTRACT_ENTER");
  rc=fw550_capture_run(FW550_FW_VERSION,data,read_disabled_once,&ctx,&report);
  if(rc!=FW550_CAPTURE_READ_ERROR || report.status!=FW550_CAPTURE_READ_ERROR ||
     report.attempted!=1u || report.verified!=0u ||
     ctx.calls!=1u || ctx.good!=1u ||
     report.receipts[0].window!=&fw550_stage_b_windows[0] ||
     report.receipts[0].requested!=21u ||
     report.receipts[0].va!=text+fw550_stage_b_windows[0].offset ||
     report.receipts[0].transfer.read_errno!=SYNTHETIC_READ_DISABLED_ERRNO ||
     report.receipts[0].transfer.returned!=-1) {
    klog_puts("E10A4P ABORT reason=CONTRACT");
    return 4;
  }
  klog_puts("E10A4P PREFLIGHT_PASS checked_reads=0 windows_prepared=1");
  return 0;
}
