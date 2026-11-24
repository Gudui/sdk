#include "../crt/kernel_copyout_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

struct mock {
  int flags_rc, addr_rc, last_errno;
  long read_result;
  int flag_calls, addr_calls, read_calls, set_errno_calls;
  int writes_destination;
};
static int flags(void *p) {
  struct mock *m=p; ++m->flag_calls; return m->flags_rc;
}
static int address(unsigned long kaddr, void *p) {
  struct mock *m=p; assert(kaddr==0xffffffff994e0000UL);
  ++m->addr_calls; return m->addr_rc;
}
static long read_once(void *dst, unsigned long len, void *p) {
  struct mock *m=p; ++m->read_calls;
  if(m->writes_destination && m->read_result>0) {
    unsigned long n=(unsigned long)m->read_result;
    assert(n<=len); memset(dst,0x53,n);
  }
  return m->read_result;
}
static int get_error(void *p) { return ((struct mock*)p)->last_errno; }
static void set_error(int v, void *p) {
  struct mock *m=p; ++m->set_errno_calls; m->last_errno=v;
}
static const struct kernel_copyout_ops OPS={flags,address,read_once,get_error,set_error};
static void scenario(int frc,int arc,long r,int err,int writes,
                     enum kernel_copyout_exact_stage stage,
                     int f,int a,int rd) {
  unsigned char dst[21]; memset(dst,0xa5,sizeof(dst));
  kernel_copyout_exact_result_t out;
  struct mock m={.flags_rc=frc,.addr_rc=arc,.last_errno=err,
                 .read_result=r,.writes_destination=writes};
  int rc=kernel_copyout_core(0xffffffff994e0000UL,dst,sizeof(dst),&out,1,&OPS,&m);
  assert(rc==(stage==KERNEL_COPYOUT_EXACT_OK?0:-1));
  assert(out.stage==stage);
  assert(out.transferred==(rd && r>0?(unsigned long)r:0));
  assert(out.syscall_attempted==rd);
  assert(out.syscall_result==(rd?r:0));
  assert(m.flag_calls==f && m.addr_calls==a && m.read_calls==rd);
  if(frc || arc || r<=0 || !writes) {
    for(unsigned i=0;i<sizeof(dst);++i) assert(dst[i]==0xa5);
  }
  if(stage==KERNEL_COPYOUT_EXACT_SYS_READ ||
     stage==KERNEL_COPYOUT_EXACT_PIPE_FLAGS ||
     stage==KERNEL_COPYOUT_EXACT_PIPE_ADDRESS)
    assert(out.error_number==err);
  if(stage==KERNEL_COPYOUT_EXACT_SHORT) assert(out.error_number==0);
}
int main(void) {
  scenario(0,0,21,0,1,KERNEL_COPYOUT_EXACT_OK,1,1,1);
  scenario(0,0,20,0,1,KERNEL_COPYOUT_EXACT_SHORT,1,1,1);
  scenario(0,0,0,0,0,KERNEL_COPYOUT_EXACT_SHORT,1,1,1);
  scenario(0,0,-1,14,0,KERNEL_COPYOUT_EXACT_SYS_READ,1,1,1);
  scenario(-1,0,21,14,0,KERNEL_COPYOUT_EXACT_PIPE_FLAGS,1,0,0);
  scenario(0,-1,21,9,0,KERNEL_COPYOUT_EXACT_PIPE_ADDRESS,1,1,0);
  scenario(0,0,21,0,0,KERNEL_COPYOUT_EXACT_OK,1,1,1);
  {
    unsigned char dst[21]; kernel_copyout_exact_result_t out;
    struct mock m={0}; memset(dst,0xa5,sizeof(dst));
    assert(kernel_copyout_core(0,dst,sizeof(dst),&out,1,&OPS,&m)==-1);
    assert(out.stage==KERNEL_COPYOUT_EXACT_INVALID && out.transferred==0);
    assert(out.error_number==22 && m.set_errno_calls==1 && m.read_calls==0);
    assert(kernel_copyout_core(0xffffffff994e0000UL,NULL,21,&out,1,&OPS,&m)==-1);
    assert(kernel_copyout_core(0xffffffff994e0000UL,dst,0,&out,1,&OPS,&m)==-1);
    assert(kernel_copyout_core(0xffffffff994e0000UL,dst,21,NULL,1,&OPS,&m)==-1);
    for(unsigned i=0;i<sizeof(dst);++i) assert(dst[i]==0xa5);
  }
  {
    unsigned char dst[21]={0}; struct mock m={.read_result=20};
    assert(kernel_copyout_core(0xffffffff994e0000UL,dst,21,NULL,0,&OPS,&m)==0);
    assert(m.read_calls==1); /* legacy positive short still accepted */
  }
  puts("PASS: shared kernel_copyout_core: exact, short, zero, negative, setup, invalid, stale, legacy ABI");
  return 0;
}
