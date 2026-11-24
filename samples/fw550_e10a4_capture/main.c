/* E10A.4: one-shot FW550 diagnostic linked to the ORIGINAL read contract.
 * No KLD, firmware writes, IDT, IPI, callbacks, patching or retries.
 * The Payload SDK CRT uses kernel pipe reads BEFORE main; no claim of ten
 * kernel reads globally, exclusive pipe ownership, timeout or fault safety. */
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "fw550_read_contract.h"

#define FW550_RAW_MASK UINT32_C(0xffff0000)
#define FW550_RAW_VERSION UINT32_C(0x05500000)

struct diagnostic_context { unsigned index; uint64_t ktext; };

static void bytes_to_hex(const unsigned char *input, size_t n, char *out) {
  const char digits[] = "0123456789abcdef";
  size_t i;
  for(i=0;i<n;++i) {
    out[i*2]=digits[input[i]>>4];
    out[i*2+1]=digits[input[i]&15];
  }
  out[n*2]=0;
}

static struct fw550_transfer_result diagnostic_read(
    uint64_t source, uint8_t *destination, size_t length, void *opaque) {
  struct diagnostic_context *ctx=(struct diagnostic_context *)opaque;
  const struct fw550_window *w=&fw550_stage_b_windows[ctx->index];
  struct fw550_transfer_result result={0};
  kernel_copyout_exact_result_t receipt;
  unsigned i=ctx->index++;
  char received_hex[FW550_MAX_WINDOW_LENGTH*2+1];
  char initial_hex[FW550_MAX_WINDOW_LENGTH*2+1];
  unsigned char original_poison[FW550_MAX_WINDOW_LENGTH];
  int rc;

  if(i>=FW550_WINDOW_COUNT || length!=w->length ||
     source!=ctx->ktext+w->offset) {
    result.read_errno=22;
    result.returned=-1;
    return result;
  }

  klog_printf("E10A4 READ_BEGIN index=%u name=%s stage=%s va=%#lx requested=%lu\n",
              i,w->site,w->stage,(unsigned long)source,(unsigned long)length);

  rc=kernel_copyout_exact((intptr_t)source,destination,length,&receipt);
  result.returned=receipt.syscall_result;
  if(receipt.stage==KERNEL_COPYOUT_EXACT_PIPE_FLAGS)
    result.flag_setup_rc=-1;
  if(receipt.stage==KERNEL_COPYOUT_EXACT_PIPE_ADDRESS)
    result.addr_setup_rc=-1;
  if(receipt.stage==KERNEL_COPYOUT_EXACT_SYS_READ ||
     receipt.stage==KERNEL_COPYOUT_EXACT_INVALID)
    result.read_errno=receipt.error_number ? receipt.error_number : 1;
  /* SDK owns a persistent pipe: there is no per-call cleanup or timeout. */
  result.cleanup_rc=0;
  result.timed_out=0;

  klog_printf("E10A4 READ_DONE index=%u rc=%d stage=%d syscall_attempted=%d signed_returned=%ld transferred=%lu errno=%d requested=%lu\n",
              i,rc,(int)receipt.stage,receipt.syscall_attempted,
              receipt.syscall_result,receipt.transferred,receipt.error_number,
              (unsigned long)length);

  if(rc==0 && receipt.stage==KERNEL_COPYOUT_EXACT_OK &&
     receipt.syscall_attempted && receipt.syscall_result==(long)length &&
     receipt.transferred==length) {
    for(size_t j=0;j<length;++j)
      original_poison[j]=(unsigned char)(w->expected[j]^0xff);
    bytes_to_hex(original_poison,length,initial_hex);
    bytes_to_hex(destination,length,received_hex);
    klog_printf("E10A4 READ_BYTES index=%u data=%s initial=%s\n",
                i,received_hex,initial_hex);
  }
  return result;
}

int main(void) {
  unsigned firmware=kernel_get_fw_version();
  uint64_t text=(uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t data=(uint64_t)KERNEL_ADDRESS_DATA_BASE;
  struct diagnostic_context ctx={0,text};
  struct fw550_capture_report report;
  enum fw550_capture_status rc;
  unsigned total=0;

  klog_printf("E10A4 START fw=%#x ktext=%#lx kdata=%#lx contract=checked_pipe_v1\n",
              firmware,(unsigned long)text,(unsigned long)data);
  if((firmware&FW550_RAW_MASK)!=FW550_RAW_VERSION ||
     text<UINT64_C(0xffff800000000000) ||
     data<text || data-text!=FW550_TEXT_LENGTH) {
    klog_puts("E10A4 ABORT reason=FIRMWARE_OR_LAYOUT");
    return 2;
  }
  for(unsigned i=0;i<FW550_WINDOW_COUNT;++i)
    total+=fw550_stage_b_windows[i].length;
  if(total!=134u) {
    klog_puts("E10A4 ABORT reason=TOTAL_NOT_134");
    return 3;
  }
  rc=fw550_capture_run(FW550_FW_VERSION,data,diagnostic_read,&ctx,&report);
  if(rc!=FW550_CAPTURE_OK || report.verified!=FW550_WINDOW_COUNT ||
     report.attempted!=FW550_WINDOW_COUNT || ctx.index!=FW550_WINDOW_COUNT) {
    klog_printf("E10A4 ABORT reason=CAPTURE status=%d verified=%u attempted=%u\n",
                (int)rc,report.verified,report.attempted);
    return 4;
  }
  klog_puts("E10A4 PASS count=10 bytes=134 complete=1");
  return 0;
}
