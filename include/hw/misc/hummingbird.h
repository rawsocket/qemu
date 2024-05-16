#ifndef HW_MISC_HUMMINGBIRD_H
#define HW_MISC_HUMMINGBIRD_H

#include <execinfo.h>

#define HB_CONFIG_REQ_QID_SUFFIX  "conf_req"
#define HB_CONFIG_RESP_QID_SUFFIX "conf_resp"
#define HB_CONFIG_QUEUE_DEPTH 8

#define HB_REG_RW_REQ_QID_SUFFIX "reg_rw_req"
#define HB_REG_RW_RESP_QID_SUFFIX "reg_rw_resp"
#define HB_REG_RW_QUEUE_DEPTH 16

#define HB_DMA_REQ_QID_SUFFIX "dma_req"
#define HB_DMA_RESP_QID_SUFFIX "dma_resp"
#define HB_DMA_QUEUE_DEPTH 16
/* Block queues for DMA data buffers */
#define HB_DMA_READ_BUFFER_QID_SUFFIX "dma_buf_read"
#define HB_DMA_WRITE_BUFFER_QID_SUFFIX "dma_buf_write"
#define HB_DMA_BUFFER_QUEUE_DEPTH 256

#define HB_MSIX_REQ_QID_SUFFIX "msix_req"
#define HB_MSIX_QUEUE_DEPTH 16

#define HB_NET_EGRESS_QID_SUFFIX "net_egress"
#define HB_NET_INGRESS_QID_SUFFIX "net_ingress"
#define HB_NET_QUEUE_DEPTH 64
/* Block queues for network packets */
/* Egress from the guest VM to the outside network through TAP interface */
#define HB_NET_EGRESS_BUFFER_QID_SUFFIX "net_buf_egress"
/* Ingress coming from the outside through TAP interface destined for the guest VM */
#define HB_NET_INGRESS_BUFFER_QID_SUFFIX "net_buf_ingress"
#define HB_NET_BUFFER_QUEUE_DEPTH 256

#define HB_BLOCK_TRANSFER_SIZE 4096

#define HB_CONCAT(x, y) x##y
#define HB_JOIN(x, y) HB_CONCAT(x, y)
#define HB_RUN_EVERY_N(n) \
  static unsigned long long HB_JOIN(ctr, __LINE__) = n - 1; \
  if (++HB_JOIN(ctr, __LINE__) == n) HB_JOIN(ctr, __LINE__) = 0; \
  if (!HB_JOIN(ctr, __LINE__))
#define HB_ADDR_IN_RANGE(addr, base, size) \
  ((addr >= base) && (addr < (base + size)))

#ifndef HB_QUOT
#define HB_QUOT(s) #s
#endif

#ifndef HB_QUOTE
#define HB_QUOTE(s) OWLNIC_QUOT(s)
#endif

static inline const char *hb_trim_filename(const char *file_name) {
#define MAX_NAME_LEN 512
  int len = strnlen(file_name, MAX_NAME_LEN);
  if (len > MAX_NAME_LEN) {
    return "Invalid filename";
  }

  return (len > 20) ? file_name + len - 20 : file_name;
}

#define HB_FMT(fmt) fmt
#define HB_LOG(level, s, format, ...) \
do { \
  char sev = (level == HB_LOG_LEVEL_ERR) ? 'E' : (level == HB_LOG_LEVEL_WARN ? 'W' : 'I'); \
  fprintf(stderr, "[PF:%d] %c:%s (%s:%d): " HB_FMT(format), \
    s->pci_dev_fn, \
    sev,  \
    __func__, \
    hb_trim_filename(__FILE__), \
    __LINE__, \
    ##__VA_ARGS__); \
  fprintf(stderr, "\x1b[0m"); \
  fflush(stderr); \
} while (0)

#define HB_LOG_LEVEL_ERR 0
#define HB_LOG_LEVEL_WARN 1
#define HB_LOG_LEVEL_INFO 2

#define HB_INFO(s, format, ...) HB_LOG(HB_LOG_LEVEL_INFO, s, format, ##__VA_ARGS__)
#define HB_WARN(s, format, ...) HB_LOG(HB_LOG_LEVEL_WARN, s, format, ##__VA_ARGS__)
#define HB_ERR(s, format, ...) HB_LOG(HB_LOG_LEVEL_ERR, s, format, ##__VA_ARGS__)

#define HB_CHECK_BT_MAX_FRAMES 16
static inline void hb_check_print_backtrace(uint8_t frames_nr) {
  void *trace[HB_CHECK_BT_MAX_FRAMES];
  char **frames;
  int i, frames_count;

  if (frames_nr > HB_CHECK_BT_MAX_FRAMES) {
    frames_nr = HB_CHECK_BT_MAX_FRAMES;
  }
  frames_count = backtrace(trace, frames_nr);
  frames = backtrace_symbols(trace, frames_count);
  if (frames) {
    fprintf(stderr, "[TRACE] Backtrace %d frames\n", frames_count);
    for (i = 0; i < frames_count; ++i) {
      fprintf(stderr, "[TRACE] %s\n", frames[i]);
    }
    fprintf(stderr, "\n");
    free(frames);
  }
}

/* Macro for crashing at runtime with location information and formattable details. */
#define HB_CHECK(cond, format, ...) do { \
  if (!(cond)) { \
    fprintf(stderr, "[CHECK] %s(%s:%d): " HB_FMT(format), \
      __func__, \
      hb_trim_filename(__FILE__), \
      __LINE__, \
      ##__VA_ARGS__); \
      hb_check_print_backtrace(HB_CHECK_BT_MAX_FRAMES); \
    abort(); \
  } \
} while (0);

#define HB_FAIL(format, ...) HB_CHECK(false, format, ##__VA_ARGS__)

#define HB_CHECK_TRUE(cond) HB_CHECK((cond), "%s", "condition: [" HB_QUOTE(cond) "] is not true")

struct HummingbirdHeader {
    uint64_t seq;
};

struct HummingbirdCompletion {
    struct HummingbirdHeader header;
    uint64_t status;
#define HB_CMPL_STATUS_OK                  (0)
#define HB_CMPL_STATUS_INVALID_PARAMETERS  (1)
#define HB_CMPL_STATUS_DUPLICATE_REQUEST   (2)
} __attribute__((packed));

struct HummingbirdConfigRequest {
    struct HummingbirdHeader header;
    uint8_t opcode;
#define HB_CONFIG_OP_GET_CONFIG 0
#define HB_CONFIG_OP_QDEV_RESET 1
} __attribute__((packed));

struct HummingbirdConfigResponse {
    struct HummingbirdCompletion completion;

    uint32_t bar0_size;
    uint32_t bar2_size;
    uint32_t bar4_size;

    uint16_t msix_num_vectors;
    uint16_t msix_pba_offset;
    uint16_t msix_cap_pos;
    uint16_t pcie_offset;
    uint16_t pmrb_offset;
    uint16_t aer_offset;
    uint16_t dsn_offset;
    uint16_t ari_offset;
    uint16_t subsys_vendor_id;
    uint16_t subsys_id;

    uint8_t mac[6];

    uint8_t msix_index;
    uint8_t msix_pba_bar_nr;
    uint8_t ari_increment;
    uint8_t bar0_prefetchable;
    uint8_t bar2_prefetchable;
    uint8_t bar4_prefetchable;

} __attribute__((packed));

struct HummingbirdUpdateRequest {
  struct HummingbirdHeader header;
  uint16_t min_q_id;
  uint16_t max_q_id;
  uint8_t opcode;
#define HB_UPDATE_ENABLE_RECEIVE 0
#define HB_UPDATE_DISABLE_RECEIVE 1
#define HB_UPDATE_FLUSH_TX_QUEUES 2
  uint8_t can_receive;
} __attribute__((packed));

struct HummingbirdUpdateResponse {
    struct HummingbirdCompletion completion;
} __attribute__((packed));

struct HummingbirdRegReadWriteRequest {
    struct HummingbirdHeader header;
    uint64_t reg_addr;
    uint64_t value_to_write;
    uint8_t op;
#define HB_REG_READ_OP 0
#define HB_REG_WRITE_OP 1
    uint8_t bar_index;
    uint8_t reg_size_bytes;
} __attribute__((packed));

struct HummingbirdRegReadWriteResponse {
    struct HummingbirdCompletion completion;
    uint64_t value_read;
    uint8_t op;
} __attribute__((packed));

struct HummingbirdRaiseMSIXRequest {
    struct HummingbirdHeader header;

    uint16_t vector_idx;
} __attribute__((packed));

struct HummingbirdDMARequest {
    struct HummingbirdHeader header;

    uint64_t dma_handle;
    uint64_t dma_data_len;
    uint8_t dma_from_device;
} __attribute__((packed));

struct HummingbirdNetPacketNotification {
    struct HummingbirdHeader header;
    uint64_t netpacket_len;
} __attribute__((packed));

struct HummingbirdBlockData {
    struct HummingbirdHeader header;
    uint8_t bytes[HB_BLOCK_TRANSFER_SIZE];
} __attribute__((packed));


#endif /* HW_MISC_HUMMINGBIRD_H */
