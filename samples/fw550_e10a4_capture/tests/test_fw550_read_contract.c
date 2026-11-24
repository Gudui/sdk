#include "../fw550_read_contract.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define TEXT UINT64_C(0xffffffff994e0000)
#define DATA (TEXT+FW550_TEXT_LENGTH)
enum fault { NONE, SHORT, ZERO, NEGATIVE, ERRNO, FLAG, ADDRESS,
             TIMEOUT, UNCHANGED, MISMATCH, CLEANUP };
struct mock {unsigned calls; int fail_index; enum fault fault;};
static struct fw550_transfer_result reader(uint64_t va, uint8_t *dst,
                                           size_t len, void *opaque) {
  struct mock *m=opaque;
  unsigned i=m->calls++;
  const struct fw550_window *w;
  struct fw550_transfer_result r={0};
  assert(i<FW550_WINDOW_COUNT);
  w=&fw550_stage_b_windows[i];
  assert(va==TEXT+w->offset && len==w->length);
  r.returned=(int64_t)len;
  if((int)i==m->fail_index && m->fault==UNCHANGED) return r;
  memcpy(dst,w->expected,len);
  if((int)i==m->fail_index) {
    switch(m->fault) {
      case SHORT:r.returned=(int64_t)len-1;break;
      case ZERO:r.returned=0;break;
      case NEGATIVE:r.returned=-1;break;
      case ERRNO:r.read_errno=14;break;
      case FLAG:r.flag_setup_rc=-1;break;
      case ADDRESS:r.addr_setup_rc=-1;break;
      case TIMEOUT:r.timed_out=1;break;
      case MISMATCH:dst[len-1]^=1;break;
      case CLEANUP:r.cleanup_rc=-1;break;
      default:assert(0);
    }
  }
  return r;
}
static void run(enum fault fault,int fail_at,enum fw550_capture_status expected) {
  struct fw550_capture_report report;
  struct mock m={0,fail_at,fault};
  enum fw550_capture_status status=fw550_capture_run(FW550_FW_VERSION,
      DATA,reader,&m,&report);
  assert(status==expected && report.status==expected);
  if(fail_at<0) {
    unsigned count=0;
    assert(m.calls==10 && report.verified==10 && report.attempted==10);
    for(unsigned i=0;i<10;++i) {
      assert(report.receipts[i].verified);
      assert(!memcmp(report.receipts[i].observed,
             report.receipts[i].window->expected,report.receipts[i].requested));
      count+=(unsigned)report.receipts[i].requested;
    }
    assert(count==134);
  } else {
    assert(m.calls==(unsigned)fail_at+1);
    assert(report.attempted==(unsigned)fail_at+1);
    assert(report.verified==(unsigned)fail_at);
  }
}
int main(void) {
  struct fw550_capture_report r;
  struct mock m={0,-1,NONE};
  run(NONE,-1,FW550_CAPTURE_OK);
  const struct {
    enum fault fault;
    enum fw550_capture_status expected;
  } cases[]={
    {SHORT,FW550_CAPTURE_SHORT_READ},{ZERO,FW550_CAPTURE_SHORT_READ},
    {NEGATIVE,FW550_CAPTURE_READ_ERROR},{ERRNO,FW550_CAPTURE_READ_ERROR},
    {FLAG,FW550_CAPTURE_SETUP_ERROR},{ADDRESS,FW550_CAPTURE_SETUP_ERROR},
    {TIMEOUT,FW550_CAPTURE_TIMEOUT},{UNCHANGED,FW550_CAPTURE_UNCHANGED},
    {MISMATCH,FW550_CAPTURE_MISMATCH},{CLEANUP,FW550_CAPTURE_CLEANUP_ERROR}
  };
  for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i) {
    run(cases[i].fault,0,cases[i].expected);
    run(cases[i].fault,5,cases[i].expected);
    run(cases[i].fault,9,cases[i].expected);
  }
  assert(fw550_capture_run(0x500,DATA,reader,&m,&r)==FW550_CAPTURE_FIRMWARE);
  assert(fw550_capture_run(FW550_FW_VERSION,0x1234,reader,&m,&r)==FW550_CAPTURE_LAYOUT);
  assert(fw550_capture_run(FW550_FW_VERSION,DATA,0,0,&r)==FW550_CAPTURE_BAD_ARGS);
  assert(fw550_capture_run(FW550_FW_VERSION,DATA,reader,&m,0)==FW550_CAPTURE_BAD_ARGS);
  assert(m.calls==0);
  puts("PASS: production FW550 capture contract 10 windows / 134 bytes, 30 failures, invalid inputs");
  return 0;
}
