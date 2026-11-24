#include "fw550_read_contract.h"
#include "fw550_windows_generated.h"
#include <limits.h>
#include <string.h>
static int valid_manifest(void) {
  unsigned i;
  for(i=0;i<FW550_WINDOW_COUNT;++i) {
    const struct fw550_window *w=&fw550_stage_b_windows[i];
    uint64_t first=w->offset, after=first+w->length;
    if(!w->site || !w->stage || !w->length ||
       w->length>FW550_MAX_WINDOW_LENGTH || first>=FW550_TEXT_LENGTH ||
       after>FW550_TEXT_LENGTH ||
       (first&UINT64_C(0xfff))+w->length>UINT64_C(0x1000))
      return 0;
  }
  return 1;
}
enum fw550_capture_status fw550_capture_run(uint32_t fw_version,
    uint64_t runtime_kdata_base, fw550_read_once_fn reader, void *reader_context,
    struct fw550_capture_report *report) {
  unsigned i; uint64_t text;
  if(!report) return FW550_CAPTURE_BAD_ARGS;
  memset(report,0,sizeof(*report));
  report->status=FW550_CAPTURE_BAD_ARGS;
  if(!reader) return report->status;
  if(fw_version!=FW550_FW_VERSION) return (report->status=FW550_CAPTURE_FIRMWARE);
  if(runtime_kdata_base<FW550_TEXT_LENGTH ||
     runtime_kdata_base>UINT64_MAX-FW550_TEXT_LENGTH)
    return (report->status=FW550_CAPTURE_LAYOUT);
  text=runtime_kdata_base-FW550_TEXT_LENGTH;
  if(text<UINT64_C(0xffff800000000000) || text>UINT64_MAX-FW550_TEXT_LENGTH)
    return (report->status=FW550_CAPTURE_LAYOUT);
  if(!valid_manifest()) return (report->status=FW550_CAPTURE_MANIFEST);
  report->kdata_base=runtime_kdata_base;
  report->ktext_base=text;
  for(i=0;i<FW550_WINDOW_COUNT;++i) {
    const struct fw550_window *w=&fw550_stage_b_windows[i];
    struct fw550_window_receipt *r=&report->receipts[i];
    size_t j;
    r->window=w; r->va=text+w->offset; r->requested=w->length;
    for(j=0;j<w->length;++j)
      r->initial[j]=(uint8_t)(w->expected[j]^UINT8_C(0xff));
    memcpy(r->observed,r->initial,w->length);
    report->attempted=i+1u;
    r->transfer=reader(r->va,r->observed,w->length,reader_context);
    if(r->transfer.timed_out) return (report->status=FW550_CAPTURE_TIMEOUT);
    if(r->transfer.cleanup_rc) return (report->status=FW550_CAPTURE_CLEANUP_ERROR);
    if(r->transfer.flag_setup_rc || r->transfer.addr_setup_rc)
      return (report->status=FW550_CAPTURE_SETUP_ERROR);
    if(r->transfer.read_errno || r->transfer.returned<0)
      return (report->status=FW550_CAPTURE_READ_ERROR);
    if((uint64_t)r->transfer.returned!=w->length)
      return (report->status=FW550_CAPTURE_SHORT_READ);
    if(!memcmp(r->observed,r->initial,w->length))
      return (report->status=FW550_CAPTURE_UNCHANGED);
    if(memcmp(r->observed,w->expected,w->length))
      return (report->status=FW550_CAPTURE_MISMATCH);
    r->verified=1; report->verified=i+1u;
  }
  return (report->status=FW550_CAPTURE_OK);
}
