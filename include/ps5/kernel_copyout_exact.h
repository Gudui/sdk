/* Checked PS5 Payload SDK pipe read contract (E10A.4).
 * A return code does not imply fault containment or concurrency safety. */
#pragma once

enum kernel_copyout_exact_stage {
  KERNEL_COPYOUT_EXACT_OK = 0,
  KERNEL_COPYOUT_EXACT_INVALID = 1,
  KERNEL_COPYOUT_EXACT_PIPE_FLAGS = 2,
  KERNEL_COPYOUT_EXACT_PIPE_ADDRESS = 3,
  KERNEL_COPYOUT_EXACT_SYS_READ = 4,
  KERNEL_COPYOUT_EXACT_SHORT = 5
};

typedef struct kernel_copyout_exact_result {
  enum kernel_copyout_exact_stage stage;
  long syscall_result;        /* signed return from SYS_read, zero until attempted */
  unsigned long transferred;  /* actual positive SYS_read count; zero otherwise */
  int syscall_attempted;
  int error_number;           /* errno snapshot from failed operation, if available */
} kernel_copyout_exact_result_t;
