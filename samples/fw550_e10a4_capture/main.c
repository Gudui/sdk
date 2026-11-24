/* E10A.4 one-shot FW550 VU identity read diagnostic.
 * NO KLD operations, firmware writes, IPIs, IDT modifications or retries.
 * The SDK CRT performs its own kernel-data reads BEFORE this main() runs.
 * Read-only does not imply panic safety. Run only after separate authorization.
 */
#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define WINDOW_COUNT 10U
#define TEXT_SIZE UINT64_C(0xc40000)
#define FW550_RAW_MASK UINT32_C(0xffff0000)
#define FW550_RAW_VERSION UINT32_C(0x05500000)
#define MAX_BYTES 21U

struct window {
  const char *name;
  const char *stage;
  uint64_t offset;
  unsigned char n;
  unsigned char expected[MAX_BYTES];
};

/* Generated from the original verified Stage B 5-site + predecessor manifest. */
static const struct window windows[WINDOW_COUNT] = {
  {"registration","site",0x7ff627,21,{0x41,0x81,0xfe,0xf8,0x06,0x00,0x00,0x0f,0x85,0x0b,0x02,0x00,0x00,0x41,0x8d,0x84,0x24,0xaf,0x1f,0x00,0x00}},
  {"registration","predecessor",0x7ff61e,9,{0x41,0x81,0xfe,0x4f,0x04,0x00,0x00,0x74,0x2b}},
  {"classification","site",0x7faba9,16,{0x81,0xf9,0xf8,0x06,0x00,0x00,0x0f,0x85,0x80,0x01,0x00,0x00,0x0f,0xb7,0x48,0x2a}},
  {"classification","predecessor",0x7fab9e,11,{0x81,0xf9,0x4f,0x04,0x00,0x00,0x74,0x24,0x0f,0xb7,0xc9}},
  {"unregistration","site",0x7ff892,19,{0x3d,0xf8,0x06,0x00,0x00,0x0f,0x85,0x0a,0x01,0x00,0x00,0x41,0x8d,0x84,0x24,0xaf,0x1f,0x00,0x00}},
  {"unregistration","predecessor",0x7ff88b,7,{0x3d,0x4f,0x04,0x00,0x00,0x74,0x29}},
  {"descriptor","site",0x7ffa53,17,{0x3d,0xf8,0x06,0x00,0x00,0x75,0x5d,0x41,0x0f,0xb7,0x46,0x2a,0x05,0xaf,0x1f,0x00,0x00}},
  {"descriptor","predecessor",0x7ffa49,7,{0x3d,0x4f,0x04,0x00,0x00,0x74,0x2a}},
  {"projection","site",0x7fb5bf,19,{0x81,0xfe,0xf8,0x06,0x00,0x00,0x75,0x39,0x41,0x0f,0xb7,0x76,0x2a,0x81,0xc6,0xaf,0x1f,0x00,0x00}},
  {"projection","predecessor",0x7fb5b4,8,{0x81,0xfe,0x4f,0x04,0x00,0x00,0x74,0x26}}
};
static void tohex(const unsigned char *bytes, unsigned n, char *out) {
  static const char digits[]="0123456789abcdef";
  unsigned i;
  for(i=0;i<n;++i) {out[i*2]=digits[bytes[i]>>4];out[i*2+1]=digits[bytes[i]&15];}
  out[n*2]=0;
}
int main(void) {
  uint32_t firmware=kernel_get_fw_version();
  uint64_t ktext=(uint64_t)KERNEL_ADDRESS_TEXT_BASE;
  uint64_t kdata=(uint64_t)KERNEL_ADDRESS_DATA_BASE;
  unsigned i, j, total=0;

  klog_printf("E10A4 START fw=%#x ktext=%#lx kdata=%#lx contract=checked_pipe_v1\n",
              firmware,(unsigned long)ktext,(unsigned long)kdata);
  if((firmware&FW550_RAW_MASK)!=FW550_RAW_VERSION ||
     ktext<UINT64_C(0xffff800000000000) ||
     kdata<ktext || kdata-ktext!=TEXT_SIZE) {
    klog_puts("E10A4 ABORT reason=FIRMWARE_OR_LAYOUT");
    return 2;
  }
  /* Entire manifest validated before any diagnostic read. */
  for(i=0;i<WINDOW_COUNT;++i) {
    const struct window *w=&windows[i];
    if(!w->n || w->n>MAX_BYTES || w->offset>=TEXT_SIZE ||
       w->offset+w->n>TEXT_SIZE || (w->offset&0xfff)+w->n>0x1000) {
      klog_printf("E10A4 ABORT reason=MANIFEST index=%u\n",i);
      return 3;
    }
    total+=w->n;
  }
  if(total!=134) {
    klog_puts("E10A4 ABORT reason=TOTAL_NOT_134");
    return 4;
  }
  for(i=0;i<WINDOW_COUNT;++i) {
    const struct window *w=&windows[i];
    unsigned char got[MAX_BYTES],poison[MAX_BYTES];
    char actual_hex[MAX_BYTES*2+1],initial_hex[MAX_BYTES*2+1];
    kernel_copyout_exact_result_t receipt;
    uint64_t address=ktext+w->offset;
    int rc;
    for(j=0;j<w->n;++j)got[j]=poison[j]=(unsigned char)(w->expected[j]^0xff);
    klog_printf("E10A4 READ_BEGIN index=%u name=%s stage=%s va=%#lx requested=%u\n",
                i,w->name,w->stage,(unsigned long)address,(unsigned)w->n);
    rc=kernel_copyout_exact((intptr_t)address,got,w->n,&receipt);
    klog_printf("E10A4 READ_DONE index=%u rc=%d stage=%d syscall_attempted=%d signed_returned=%ld transferred=%lu errno=%d requested=%u\n",
                i,rc,(int)receipt.stage,receipt.syscall_attempted,
                receipt.syscall_result,receipt.transferred,receipt.error_number,
                (unsigned)w->n);
    if(rc || receipt.stage!=KERNEL_COPYOUT_EXACT_OK ||
       !receipt.syscall_attempted || receipt.syscall_result!=(long)w->n ||
       receipt.transferred!=(unsigned long)w->n) {
      klog_printf("E10A4 ABORT reason=READ_ERROR index=%u\n",i);
      return 5;
    }
    tohex(got,w->n,actual_hex);
    tohex(poison,w->n,initial_hex);
    klog_printf("E10A4 READ_BYTES index=%u data=%s initial=%s\n",
                i,actual_hex,initial_hex);
    if(!memcmp(got,poison,w->n) || memcmp(got,w->expected,w->n)) {
      klog_printf("E10A4 ABORT reason=BYTE_MISMATCH index=%u\n",i);
      return 6;
    }
  }
  klog_puts("E10A4 PASS count=10 bytes=134 complete=1");
  return 0;
}
