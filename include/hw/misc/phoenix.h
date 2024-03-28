#ifndef HW_MISC_PHOENIX_H
#define HW_MISC_PHOENIX_H

struct PhoenixHeader {
    uint64_t sequence;
};

struct PhoenixCompletion {
    struct PhoenixHeader header;
    uint64_t status;
#define PHOENIX_CMPL_STATUS_OK                  (0)
#define PHOENIX_CMPL_STATUS_INVALID_PARAMETERS  (1)
#define PHOENIX_CMPL_STATUS_DUPLICATE_REQUEST   (2)
} __attribute__((packed));

struct PhoenixConfigRequest {
    struct PhoenixHeader header;
} __attribute__((packed));

struct PhoenixConfigResponse {
    struct PhoenixCompletion completion;

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

struct PhoenixRegWriteRequest {
    struct PhoenixHeader header;

    uint64_t bar_index:3;
    uint64_t reg_index:29;
    uint64_t reg_size_bytes:8;
    uint64_t reserved_0:24;
    uint64_t value;
} __attribute__((packed));

struct PhoenixRegReadRequest {
    struct PhoenixHeader header;

    uint64_t bar_index:3;
    uint64_t reg_index:29;
    uint64_t reg_size_bytes:8;
    uint64_t reserved_0:24;
} __attribute__((packed));

struct PhoenixRegReadResponse {
    struct PhoenixCompletion completion;

    uint64_t value;
} __attribute__((packed));

struct PhoenixRaiseMSIXRequest {
    struct PhoenixHeader header;

    uint64_t vector_index:16;
} __attribute__((packed));

struct PhoenixDmaRequest {
    struct PhoenixHeader header;

    uint64_t dma_handle;
    uint64_t dma_data_length;
    uint8_t dma_from_device;
} __attribute__((packed));


struct PhoenixNetPacketNotification {
    struct PhoenixHeader header;

    uint64_t netpacket_length;
} __attribute__((packed));

struct PhoenixBlockata {
#define PHOENIX_BLOCK_TRANSFER_SIZE 4096
    uint8_t bytes[PHOENIX_BLOCK_TRANSFER_SIZE];
} __attribute__((packed));


#endif /* HW_MISC_PHOENIX_H */
