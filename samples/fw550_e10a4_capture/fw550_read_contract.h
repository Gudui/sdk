/* E10A.4: existing host-tested FW550 ten-window contract.
 * This structure is independent of the kernel-access mechanism. */
#ifndef FW550_READ_CONTRACT_H
#define FW550_READ_CONTRACT_H
#include <stddef.h>
#include <stdint.h>
#define FW550_TEXT_LENGTH UINT64_C(0xC40000)
#define FW550_FW_VERSION UINT32_C(0x550)
#define FW550_WINDOW_COUNT 10u
#define FW550_MAX_WINDOW_LENGTH 21u
struct fw550_window {
  const char *site;
  const char *stage;
  uint64_t offset;
  uint8_t length;
  uint8_t expected[FW550_MAX_WINDOW_LENGTH];
};
struct fw550_transfer_result {
  int flag_setup_rc;
  int addr_setup_rc;
  int read_errno;
  int cleanup_rc; /* Zero when no per-read cleanup is provided */
  int timed_out;  /* Zero does not imply timeout enforcement */
  int64_t returned;
};
typedef struct fw550_transfer_result (*fw550_read_once_fn)(
  uint64_t source_va, uint8_t *destination, size_t length, void *context);
enum fw550_capture_status {
  FW550_CAPTURE_OK=0, FW550_CAPTURE_BAD_ARGS=1, FW550_CAPTURE_FIRMWARE=2,
  FW550_CAPTURE_LAYOUT=3, FW550_CAPTURE_MANIFEST=4, FW550_CAPTURE_SETUP_ERROR=5,
  FW550_CAPTURE_READ_ERROR=6, FW550_CAPTURE_SHORT_READ=7,
  FW550_CAPTURE_TIMEOUT=8, FW550_CAPTURE_UNCHANGED=9,
  FW550_CAPTURE_MISMATCH=10, FW550_CAPTURE_CLEANUP_ERROR=11
};
struct fw550_window_receipt {
  const struct fw550_window *window;
  uint64_t va;
  size_t requested;
  struct fw550_transfer_result transfer;
  uint8_t initial[FW550_MAX_WINDOW_LENGTH];
  uint8_t observed[FW550_MAX_WINDOW_LENGTH];
  int verified;
};
struct fw550_capture_report {
  uint64_t ktext_base;
  uint64_t kdata_base;
  enum fw550_capture_status status;
  unsigned attempted;
  unsigned verified;
  struct fw550_window_receipt receipts[FW550_WINDOW_COUNT];
};
extern const struct fw550_window fw550_stage_b_windows[FW550_WINDOW_COUNT];
enum fw550_capture_status fw550_capture_run(uint32_t fw_version,
    uint64_t runtime_kdata_base, fw550_read_once_fn reader, void *reader_context,
    struct fw550_capture_report *report);
#endif
