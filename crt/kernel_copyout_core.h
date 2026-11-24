/* Shared state machine for legacy and exact kernel_copyout.
 * Host regressions compile this exact code with injected transport callbacks.
 * Does not claim pipe reads are fault-contained, reentrant or cancellable. */
#pragma once
#include "../include/ps5/kernel_copyout_exact.h"

struct kernel_copyout_ops {
  int (*setup_flags)(void *ctx);
  int (*setup_address)(unsigned long kaddr, void *ctx);
  long (*read_once)(void *dst, unsigned long len, void *ctx);
  int (*get_errno)(void *ctx);
  void (*set_errno)(int value, void *ctx);
};

static int
kernel_copyout_core(unsigned long kaddr, void *dst, unsigned long len,
                    kernel_copyout_exact_result_t *out, int require_exact,
                    const struct kernel_copyout_ops *ops, void *ctx) {
  long nread;
  if(out) {
    out->stage = KERNEL_COPYOUT_EXACT_INVALID;
    out->syscall_result = 0;
    out->transferred = 0;
    out->syscall_attempted = 0;
    out->error_number = 0;
  }
  if(!kaddr || !dst || !len || (require_exact && !out)) {
    ops->set_errno(22, ctx); /* EINVAL, same as original kernel_copyout */
    if(out) out->error_number = 22;
    return -1;
  }
  if(ops->setup_flags(ctx)) {
    if(out) {
      out->stage = KERNEL_COPYOUT_EXACT_PIPE_FLAGS;
      out->error_number = ops->get_errno(ctx);
    }
    return -1;
  }
  if(ops->setup_address(kaddr, ctx)) {
    if(out) {
      out->stage = KERNEL_COPYOUT_EXACT_PIPE_ADDRESS;
      out->error_number = ops->get_errno(ctx);
    }
    return -1;
  }
  nread = ops->read_once(dst, len, ctx); /* exactly one attempt, never retry */
  if(out) {
    out->syscall_attempted = 1;
    out->syscall_result = nread;
    if(nread > 0) out->transferred = (unsigned long)nread;
  }
  if(nread < 0) {
    if(out) {
      out->stage = KERNEL_COPYOUT_EXACT_SYS_READ;
      out->error_number = ops->get_errno(ctx);
    }
    return -1;
  }
  if(require_exact && (unsigned long)nread != len) {
    if(out) out->stage = KERNEL_COPYOUT_EXACT_SHORT;
    return -1;
  }
  if(out) out->stage = KERNEL_COPYOUT_EXACT_OK;
  return 0;
}
