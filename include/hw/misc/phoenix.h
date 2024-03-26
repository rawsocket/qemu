#ifndef HW_MISC_PHOENIX_H
#define HW_MISC_PHOENIX_H

#define PHOENIX_PROTO_PROXY_OP_PCIE_CONFIG   0UL
#define PHOENIX_PROTO_PROXY_OP_WRITE_REQ     1UL
#define PHOENIX_PROTO_PROXY_OP_READ_REQ      2UL
#define PHOENIX_PROTO_PROXY_OP_READ_RESP     3UL
#define PHOENIX_PROTO_PROXY_OP_DMA_READ_REQ  4UL
#define PHOENIX_PROTO_PROXY_OP_DMA_READ_RESP 5UL
#define PHOENIX_PROTO_PROXY_OP_DMA_WRITE_REQ 6UL
#define PHOENIX_PROTO_PROXY_OP_MSIX_REQ      7UL
#define PHOENIX_PROTO_PROXY_OP_NETPACKET     8UL

struct phoenix_header {
    uint64_t sequence;
};

struct phoenix_completion {
    struct phoenix_header header;
    uint64_t status;
#define PHOENIX_CMPL_STATUS_OK      (0)
#define PHOENIX_CMPL_STATUS_FAIL    (1)
};

struct phoenix_config_db {
    struct phoenix_header header;

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

struct phoenix_reg_write_db {
    struct phoenix_header header;

    uint64_t bar_index:3;
    uint64_t reg_index:29;
    uint64_t reg_size_bytes:8;
    uint64_t reserved_0:24;
    uint64_t value;
};

struct phoenix_reg_read_db {
    struct phoenix_header header;

    uint64_t bar_index:3;
    uint64_t reg_index:29;
    uint64_t reg_size_bytes:8;
    uint64_t reserved_0:24;
};

struct phoenix_reg_read_db_response {
    struct phoenix_completion completion;

    uint64_t value;
};

struct phoenix_raise_msix_db {
    struct phoenix_header header;

    uint64_t vector_index:16;
};

struct phoenix_dma_db {
    struct phoenix_header header;

    uint64_t dma_handle;
    uint64_t dma_from_device:1;
    uint64_t dma_data_length:63;
};

struct phoenix_netpacket_db {
    struct phoenix_header header;

    uint64_t netpacket_length;
};

#endif /* HW_MISC_PHOENIX_H */
