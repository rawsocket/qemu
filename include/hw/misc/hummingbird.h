#ifndef HW_MISC_HUMMINGBIRD_H
#define HW_MISC_HUMMINGBIRD_H

struct HummingbirdHeader {
    uint64_t sequence;
};

struct HummingbirdCompletion {
    struct HummingbirdHeader header;
    uint64_t status;
#define HUMMINGBIRD_CMPL_STATUS_OK                  (0)
#define HUMMINGBIRD_CMPL_STATUS_INVALID_PARAMETERS  (1)
#define HUMMINGBIRD_CMPL_STATUS_DUPLICATE_REQUEST   (2)
} __attribute__((packed));

struct HummingbirdConfigRequest {
    struct HummingbirdHeader header;
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

#define HUMMINGBIRD_REG_READ_OP 0
#define HUMMINGBIRD_REG_WRITE_OP 1

struct HummingbirdRegReadWriteRequest {
    struct HummingbirdHeader header;
    uint64_t reg_index;
    uint64_t value_to_write;
    uint8_t op;
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

    uint64_t vector_index:16;
} __attribute__((packed));

struct HummingbirdDmaRequest {
    struct HummingbirdHeader header;

    uint64_t dma_handle;
    uint64_t dma_data_length;
    uint8_t dma_from_device;
} __attribute__((packed));


struct HummingbirdNetPacketNotification {
    struct HummingbirdHeader header;

    uint64_t netpacket_length;
} __attribute__((packed));

struct HummingbirdBlockata {
#define HUMMINGBIRD_BLOCK_TRANSFER_SIZE 4096
    uint8_t bytes[HUMMINGBIRD_BLOCK_TRANSFER_SIZE];
} __attribute__((packed));


#endif /* HW_MISC_HUMMINGBIRD_H */
