/*
 * Hummingbird: A pass-though PCIE device to allow external hardware models.
 *
 * Adel Abouchaev <adelab@meta.com>
 *
 * Based on work done by:
 * Alexander Duyck <alexanderduyck@fb.com>
 * Copyright (c) 2015 Ravello Systems LTD (http://ravellosystems.com)
 * Developed by Daynix Computing LTD (http://www.daynix.com)
 * Dmitry Fleytman <dmitry@daynix.com>
 * Leonid Bloch <leonid@daynix.com>
 * Yan Vugenfirer <yan@daynix.com>
 * Nir Peleg, Tutis Systems Ltd. for Qumranet Inc.
 * Copyright (c) 2008 Qumranet
 * Based on work done by:
 * Copyright (c) 2007 Dan Aloni
 * Copyright (c) 2004 Antony T Curtis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include <linux/types.h>
#include <linux/stddef.h>

#include "qemu/osdep.h"
#include "qemu/range.h"
#include "qemu/thread.h"
#include "qemu/typedefs.h"
#include "qemu/units.h"

#include "sysemu/dma.h"
#include "sysemu/sysemu.h"

#include "qemu/module.h"

#include "net/net.h"
#include "qapi/error.h"

#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/qdev-properties.h"

#include "migration/vmstate.h"

#include "hw/misc/hummingbird.h"
#include "hw/misc/queue.h"

struct BarConfig {
  struct MemoryRegion bar;
  uint32_t size;
  bool prefetch;
};

typedef struct HummingbirdState {
  PCIDevice parent_obj;
  NICConf conf;
  NICState *nic;

  uint16_t subsys;
  uint16_t subsys_ven;
  uint16_t subsys_ven_used;
  uint16_t subsys_used;
  uint16_t pci_id;
  uint16_t pci_dev_fn;

  uint16_t msix_index;
  uint16_t msix_num_vectors;

  struct BarConfig bar[6];
  uint8_t mac[6];
  uint8_t link;
  char *qid_prefix;

  QemuThread consumer_thread;
  bool run_consumer_thread;
} HummingbirdState;

#define TYPE_HUMMINGBIRD "hummingbird"
#define HUMMINGBIRD(obj) OBJECT_CHECK(HummingbirdState, (obj), TYPE_HUMMINGBIRD)

static void sleep_nanoseconds(uint64_t nano_secs) {
  struct timespec t_req = {0, nano_secs};
  struct timespec t_rem = {0, 0};

  while (nanosleep(&t_req, &t_rem) != 0) {
    if (errno != EINTR) {
      break;
    }
    t_req = t_rem;
  }
}

static void hb_write_config(PCIDevice *pci_dev, uint32_t address,
                                 uint32_t val, int len) {
  pci_default_write_config(pci_dev, address, val, len);
}

static void hb_unuse_msix_vectors(struct HummingbirdState *s) {
  for (int i = 0; i < s->msix_num_vectors; ++i)
    msix_vector_unuse(PCI_DEVICE(s), i);
}

static void hb_use_msix_vectors(HummingbirdState *s) {
  for (int i = 0; i < s->msix_num_vectors; ++i) {
    HB_INFO(s, "Using MSI-X vector %d/%d out of %d\n", i, s->msix_num_vectors, PCI_DEVICE(s)->msix_entries_nr);
    msix_vector_use(PCI_DEVICE(s), i);
  }
}

static void hb_init_msix(struct HummingbirdState *s, struct HummingbirdConfigResponse *config) {
  PCIDevice *d = PCI_DEVICE(s);
  struct Error *err = 0;
  s->msix_index = config->msix_index;
  s->msix_num_vectors = config->msix_num_vectors;

  HB_INFO(s,
          "s->msix_num_vectors = %d, s->msix_index = %d, config->msix_pba_bar_nr = %d, config->msix_pba_offset = %d, config->msix_cap_pos = %d\n",
          s->msix_num_vectors, s->msix_index, config->msix_pba_bar_nr, config->msix_pba_offset, config->msix_cap_pos);

  int res =
      msix_init(d, s->msix_num_vectors, &s->bar[s->msix_index].bar,
                s->msix_index, /* MSIX TABLE */0, &s->bar[s->msix_index].bar,
                config->msix_pba_bar_nr, config->msix_pba_offset, config->msix_cap_pos, &err);

  if (res >= 0) {
    hb_use_msix_vectors(s);
    return;
  }

  HB_ERR(s, "Failed to use MSI-X vectors\n");
}

static void hb_cleanup_msix(struct HummingbirdState *s) {
  if (msix_present(PCI_DEVICE(s))) {
    hb_unuse_msix_vectors(s);
    msix_uninit(PCI_DEVICE(s), &s->bar[s->msix_index].bar,
                &s->bar[s->msix_index].bar);
  }
}

#define IS_PRODUCER true
#define IS_CONSUMER false

#define DEFINE_QUEUE_ATTRS(ID, TYPE, DEPTH, PROD) \
struct QueueAttrs ID = { \
  .qid = "", \
  .desc_size = sizeof(struct TYPE), \
  .num_descs = DEPTH, \
  .last_cons = 0, \
  .last_prod = 0, \
  .is_a_producer = PROD, \
};

DEFINE_QUEUE_ATTRS(config_req_attrs, HummingbirdConfigRequest, HB_CONFIG_QUEUE_DEPTH, IS_PRODUCER);
DEFINE_QUEUE_ATTRS(config_resp_attrs, HummingbirdConfigResponse, HB_CONFIG_QUEUE_DEPTH, IS_CONSUMER);

DEFINE_QUEUE_ATTRS(reg_rw_req_attrs, HummingbirdRegReadWriteRequest, HB_REG_RW_QUEUE_DEPTH, IS_PRODUCER);
DEFINE_QUEUE_ATTRS(reg_rw_resp_attrs, HummingbirdRegReadWriteResponse, HB_REG_RW_QUEUE_DEPTH, IS_CONSUMER);

DEFINE_QUEUE_ATTRS(dma_req_attrs, HummingbirdDMARequest, HB_DMA_QUEUE_DEPTH, IS_CONSUMER);
DEFINE_QUEUE_ATTRS(dma_resp_attrs, HummingbirdCompletion, HB_DMA_QUEUE_DEPTH, IS_PRODUCER);
DEFINE_QUEUE_ATTRS(dma_read_buf_attrs, HummingbirdBlockData, HB_DMA_BUFFER_QUEUE_DEPTH, IS_PRODUCER);
DEFINE_QUEUE_ATTRS(dma_write_buf_attrs, HummingbirdBlockData, HB_DMA_BUFFER_QUEUE_DEPTH, IS_CONSUMER);

DEFINE_QUEUE_ATTRS(msix_req_attrs, HummingbirdRaiseMSIXRequest, HB_MSIX_QUEUE_DEPTH, IS_CONSUMER);

DEFINE_QUEUE_ATTRS(netpacket_to_guest_notif_attrs, HummingbirdNetPacketNotification, HB_NET_QUEUE_DEPTH, IS_PRODUCER);
DEFINE_QUEUE_ATTRS(netpacket_to_guest_buf_attrs, HummingbirdBlockData, HB_NET_BUFFER_QUEUE_DEPTH, IS_PRODUCER);
DEFINE_QUEUE_ATTRS(netpacket_from_guest_notif_attrs, HummingbirdNetPacketNotification, HB_NET_QUEUE_DEPTH, IS_CONSUMER);
DEFINE_QUEUE_ATTRS(netpacket_from_guest_buf_attrs, HummingbirdBlockData, HB_NET_BUFFER_QUEUE_DEPTH, IS_CONSUMER);

static inline uint64_t hb_read(void *opaque, int bar_index, hwaddr addr,
                                    unsigned size) {
  static uint64_t seq = 0;
  struct HummingbirdState *s = (struct HummingbirdState *)opaque;
  struct HummingbirdRegReadWriteRequest req = {
    .header = {
      .seq = seq++,
    },
    .reg_addr = addr,
    .op = HB_REG_READ_OP,
    .bar_index = bar_index,
    .reg_size_bytes = size,
  };

  static const int READ_PAUSE_NS = 1000;
  static const int READ_RETRY_NUM = 100;

  HB_INFO(s, "Read from BAR%d, addr 0x%lx\n", bar_index, addr);
  int rc = enqueue(&reg_rw_req_attrs, &req);
  if (rc) {
    HB_ERR(s, "Failed to enqueue reg read request\n");
    return rc;
  }

  struct HummingbirdRegReadWriteResponse resp;

  rc = dequeue(&reg_rw_resp_attrs, (uint8_t *)&resp);
  int retries = READ_RETRY_NUM;
  while (rc == -EAGAIN && retries > 0) {
    HB_INFO(s, "Waiting for the reg read response from the model backend.\n");
    sleep_nanoseconds(READ_PAUSE_NS);
    rc = dequeue(&config_resp_attrs, (uint8_t *)&resp);
    retries--;
  }

  if (rc) {
    HB_ERR(s, "Failed to dequeue reg read response\n");
    return rc;
  }

  if (!retries) {
    HB_ERR(s, "Timed out waiting for the reg response from the model backend.\n");
    return -1;
  }

  if (resp.completion.status != HB_CMPL_STATUS_OK) {
    HB_ERR(s, "Failed to read from BAR%d, addr 0x%lx\n", bar_index, addr);
    return -1;
  }

  if (resp.completion.header.seq != req.header.seq) {
    HB_ERR(s, "Read response seq %ld does not match request seq %ld\n", resp.completion.header.seq, req.header.seq);
    return -1;
  }

  return resp.value_read;
}

static inline void hb_write(void *opaque, int bar_index, hwaddr addr,
                                 uint64_t val, unsigned size) {
  static uint64_t seq = 0;
  struct HummingbirdState *s = (struct HummingbirdState *)opaque;
  struct HummingbirdRegReadWriteRequest req = {
    .header = {
      .seq = seq++,
    },
    .reg_addr = addr,
    .op = HB_REG_WRITE_OP,
    .bar_index = bar_index,
    .reg_size_bytes = size,
    .value_to_write = val,
  };

  static const int WRITE_PAUSE_NS = 1000;
  static const int WRITE_RETRY_NUM = 100;

  HB_INFO(s, "Write to BAR%d, addr 0x%lx\n", bar_index, addr);
  int rc = enqueue(&reg_rw_req_attrs, &req);
  if (rc) {
    HB_ERR(s, "Failed to enqueue reg write request\n");
    return;
  }

  struct HummingbirdRegReadWriteResponse resp;

  rc = dequeue(&reg_rw_resp_attrs, (uint8_t *)&resp);
  int retries = WRITE_RETRY_NUM;
  while (rc == -EAGAIN && retries > 0) {
    HB_INFO(s, "Waiting for the reg write response from the model backend.\n");
    sleep_nanoseconds(WRITE_PAUSE_NS);
    rc = dequeue(&config_resp_attrs, (uint8_t *)&resp);
    retries--;
  }

  if (rc) {
    HB_ERR(s, "Failed to dequeue reg read response\n");
    return;
  }

  if (!retries) {
    HB_ERR(s, "Timed out waiting for the reg response from the model backend.\n");
    return;
  }

  if (resp.completion.status != HB_CMPL_STATUS_OK) {
    HB_ERR(s, "Failed to read from BAR%d, addr 0x%lx\n", bar_index, addr);
    return;
  }

  if (resp.completion.header.seq != req.header.seq) {
    HB_ERR(s, "Read response seq %ld does not match request seq %ld\n", resp.completion.header.seq, req.header.seq);
    return;
  }
}

static uint64_t hb_bar0_read(void *opaque, hwaddr addr, unsigned size) {
  return hb_read(opaque, 0, addr, size);
}

static uint64_t hb_bar2_read(void *opaque, hwaddr addr, unsigned size) {
  return hb_read(opaque, 2, addr, size);
}

static uint64_t hb_bar4_read(void *opaque, hwaddr addr, unsigned size) {
  return hb_read(opaque, 4, addr, size);
}

static void hb_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  hb_write(opaque, 0, addr, val, size);
}

static void hb_bar2_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  hb_write(opaque, 2, addr, val, size);
}

static void hb_bar4_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  hb_write(opaque, 4, addr, val, size);
}

static const MemoryRegionOps hb_bar_ops[6] = {
    {
        .read = hb_bar0_read,
        .write = hb_bar0_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
    {
        .read = hb_bar2_read,
        .write = hb_bar2_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
    {
        .read = hb_bar4_read,
        .write = hb_bar4_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
};

static int hb_add_pm_capability(PCIDevice *pdev, uint8_t offset,
                                     uint16_t pmc) {
  Error *local_err = NULL;
  int ret = pci_add_capability(pdev, PCI_CAP_ID_PM, offset, PCI_PM_SIZEOF,
                               &local_err);

  if (local_err) {
    error_report_err(local_err);
    return ret;
  }

  pci_set_word(pdev->config + offset + PCI_PM_PMC, PCI_PM_CAP_VER_1_1 | pmc);

  pci_set_word(pdev->wmask + offset + PCI_PM_CTRL,
               PCI_PM_CTRL_STATE_MASK | PCI_PM_CTRL_PME_ENABLE |
                   PCI_PM_CTRL_DATA_SEL_MASK);

  pci_set_word(pdev->w1cmask + offset + PCI_PM_CTRL, PCI_PM_CTRL_PME_STATUS);

  return ret;
}

/* Update ARI to allow device id skips. */
static void hb_pcie_ari_init(PCIDevice *dev, uint16_t offset,
                                  uint8_t nextfn) {
  if (!(dev->cap_present & QEMU_PCIE_ARI_NEXTFN_1)) {
    nextfn = 0;
  }

  pcie_add_capability(dev, PCI_EXT_CAP_ID_ARI, PCI_ARI_VER, offset,
                      PCI_ARI_SIZEOF);
  pci_set_long(dev->config + offset + PCI_ARI_CAP, (nextfn & 0xff) << 8);
}

static void hb_set_link_status(NetClientState* nc) {
  struct HummingbirdState *s = (struct HummingbirdState *)qemu_get_nic_opaque(nc);
  uint8_t stale_link = s->link;
  s->link = !nc->link_down;
  if (s->link != stale_link) {
    HB_ERR(s,
        "OWLNIC link status changed %s => %s\n",
        stale_link ? "UP" : "DOWN",
        s->link ? "UP" : "DOWN");
  }
}

static bool hb_can_receive(NetClientState *nc) { return TRUE; }

static ssize_t hb_receive_iov(NetClientState *nc, const struct iovec *iov,
                            int iovcnt) {
  ssize_t total = iov_size(iov, iovcnt);

  /* Transmit received frame to the model */

  return total;
}

static ssize_t hb_receive(NetClientState *nc, const uint8_t *buf, size_t size) {
  const struct iovec iov = {.iov_base = (uint8_t *)buf, .iov_len = size};
  return hb_receive_iov(nc, &iov, 1);
}

static NetClientInfo net_hb_mac_info = {.type = NET_CLIENT_DRIVER_NIC,
                                            .size = sizeof(NICState),
                                            .can_receive = hb_can_receive,
                                            .receive = hb_receive,
                                            .receive_iov = hb_receive_iov,
                                            .link_status_changed =
                                                hb_set_link_status};

static inline uint64_t hb_gen_dsn(uint8_t *mac) {
  return (uint64_t)(mac[5]) | (uint64_t)(mac[4]) << 8 |
         (uint64_t)(mac[3]) << 16 | (uint64_t)(0x00FF) << 24 |
         (uint64_t)(0x00FF) << 32 | (uint64_t)(mac[2]) << 40 |
         (uint64_t)(mac[1]) << 48 | (uint64_t)(mac[0]) << 56;
}

static void hb_format_nic_info_str(NetClientState *nc, const char *type,
                                       uint8_t macaddr[6]) {
  snprintf(nc->info_str, sizeof(nc->info_str),
           "model=%s,type=%s,macaddr=%02x:%02x:%02x:%02x:%02x:%02x", nc->model,
           type, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4],
           macaddr[5]);
}



#define CONNECT_QUEUE_OR_RETURN_ERROR(S, ATTRS, SUFFIX) \
do { \
  snprintf(ATTRS.qid, sizeof(ATTRS.qid), "%s%s", s->qid_prefix, SUFFIX); \
  int rc = connect_queue(&ATTRS, 10); \
  if (rc) { \
    HB_ERR(S, "Failed to connect to the " #ATTRS " queue [%s]\n", ATTRS.qid); \
    return -1; \
  } \
} while(0);

#define DMA_BUF_REPEATS 10

static void *try_get_cons_desc_addr(struct QueueAttrs *attrs) {
  void *cons_desc_addr = NULL;

  for (int i = 0; i < DMA_BUF_REPEATS; ++i) {
    cons_desc_addr = get_current_cons_desc(attrs);
    if (cons_desc_addr)
      return cons_desc_addr;

    sleep_nanoseconds(1000000); /* 1 msec */
  }

  return NULL;
}

static void *try_get_prod_desc_addr(struct QueueAttrs *attrs) {
  void *prod_desc_addr = NULL;

  for (int i = 0; i < DMA_BUF_REPEATS; ++i) {
    prod_desc_addr = get_current_prod_desc(attrs);
    if (prod_desc_addr)
      return prod_desc_addr;

    sleep_nanoseconds(1000000); /* 1 msec */
  }

  return NULL;
}

static int hb_exec_dma_write(
  const struct HummingbirdState *s, const struct HummingbirdDMARequest *dma_req) {
  /* Write to VM memory */
  uint64_t addr = dma_req->dma_handle;
  uint64_t len = dma_req->dma_data_len;
  int rc = 0;
  uint64_t seq = dma_req->header.seq;

  while (len > 0) {
    uint64_t transfer_size =
      (len >= HB_BLOCK_TRANSFER_SIZE)
      ? HB_BLOCK_TRANSFER_SIZE : len;

    rc = 0;
    struct HummingbirdBlockData *current_cons_desc =
      try_get_cons_desc_addr(&dma_write_buf_attrs);

    if (!current_cons_desc) {
      HB_ERR(s,
        "Failed to get pointer to current cons item from the queue [%s]\n",
        dma_write_buf_attrs.qid);
      rc = -1;
      break;
    }

    if (current_cons_desc->header.seq != seq) {
      HB_ERR(s, "DMA seq mismatch, expected %lx, got %lx, ignoring the buffer\n",
        seq, current_cons_desc->header.seq);
      rc = -1;
      break;
    }

    pci_dma_write((PCIDevice *)&s->parent_obj, addr, &current_cons_desc->bytes, transfer_size);
    addr += transfer_size;
    len -= transfer_size;
    seq++;

    rc = advance_cons_and_post(&dma_write_buf_attrs);
    if (rc) {
      HB_ERR(s,
        "Failed to advance cons from the queue [%s]\n",
        dma_write_buf_attrs.qid);
      break;
    }
  }

  struct HummingbirdCompletion completion = {
    .header = {
      .seq = dma_req->header.seq,
    },
    .status = rc ? HB_CMPL_STATUS_INVALID_PARAMETERS : HB_CMPL_STATUS_OK,
  };

  int cmpl_rc = enqueue(&dma_resp_attrs, &completion);

  if (cmpl_rc) {
    HB_ERR(s,
      "Failed to enqueue VM memory DMA write completion\n");
  }

  return rc;
}

static int hb_exec_dma_read(
  const struct HummingbirdState *s,
  const struct HummingbirdDMARequest *dma_req) {
  /* Read from VM memory */
  uint64_t addr = dma_req->dma_handle;
  uint64_t len = dma_req->dma_data_len;
  uint64_t transfer_size;
  uint64_t seq = dma_req->header.seq;

  int rc = 0;
  while (len > 0) {
    if (len >= HB_BLOCK_TRANSFER_SIZE) {
      transfer_size = HB_BLOCK_TRANSFER_SIZE;
    } else {
      transfer_size = len;
    }

    struct HummingbirdBlockData *current_prod_desc =
      try_get_prod_desc_addr(&dma_read_buf_attrs);

    if (!current_prod_desc) {
      HB_ERR(s,
        "Failed to get inline pointer for the DMA data to the queue [%s]\n",
        dma_read_buf_attrs.qid);
      rc = -1;
      break;
    }

    current_prod_desc->header.seq = seq++;
    pci_dma_read((PCIDevice *)&s->parent_obj, addr, current_prod_desc->bytes, transfer_size);
    addr += transfer_size;
    len -= transfer_size;

    rc = advance_prod_and_post(&dma_read_buf_attrs);
    if (rc) {
      HB_ERR(s,
        "Failed to enqueue the DMA data to the queue [%s]\n",
        dma_read_buf_attrs.qid);
      rc = -1;
      break;
    }
  }
  if (rc) {
    HB_ERR(s,
      "Failed to enqueue DMA read from the VM memory [%lx]\n",
      dma_req->dma_handle);
  }
  struct HummingbirdCompletion completion = {
    .header = {
      .seq = dma_req->header.seq,
    },
    .status = rc ? HB_CMPL_STATUS_INVALID_PARAMETERS : HB_CMPL_STATUS_OK,
  };

  int cmpl_rc = enqueue(&dma_resp_attrs, &completion);
  if (cmpl_rc) {
    HB_ERR(s,
      "Failed to enqueue VM memory DMA write completion\n");
  }

  return rc;
}

static int hb_try_exec_dma_ops(const struct HummingbirdState *s) {
  /* DMA */
  struct HummingbirdDMARequest dma_req;
  int rc;

  rc = dequeue(&dma_req_attrs, &dma_req);
  if (rc == 0) {
    /* DMA requested */
    if (dma_req.dma_from_device) {
      /* Write to VM memory */
      rc = hb_exec_dma_write(s, &dma_req);
      if (rc) {
        HB_ERR(s, "Failed to enqueue DMA write to the VM memory [%lx], stopping processing\n", dma_req.dma_handle);
      }
    } else {
      /* Read from VM memory */
      rc = hb_exec_dma_read(s, &dma_req);
      if (rc) {
        HB_ERR(s,
          "Failed to enqueue DMA read from the VM memory [%lx]\n",
          dma_req.dma_handle);
      }
    }
  }
  return rc;
}

static void hb_try_exec_msix_ops(const struct HummingbirdState *s) {
  /* MSIX */
  struct HummingbirdRaiseMSIXRequest msix_req;

  if (dequeue(&msix_req_attrs, &msix_req) != 0)
    return;

  /* MSIX requested */
  if (msix_enabled(PCI_DEVICE(s))) {
    msix_notify(PCI_DEVICE(s), msix_req.vector_idx);
  } else {
    HB_ERR(s, "MSIX is not enabled on the device\n");
  }
}

static int hb_exec_netpacket_egress(const struct HummingbirdState *s,
  struct HummingbirdNetPacketNotification *netpacket_req) {
  int rc = 0;
  uint64_t next_buf_seq = netpacket_req->header.seq;
  uint64_t bytes_to_read = netpacket_req->netpacket_len;
  uint64_t transfer_size;

#define HB_MAX_MTU_SIZE 9100
#define HB_ETH_HEADER_SIZE 14

  uint8_t netpacket_content[HB_MAX_MTU_SIZE + HB_ETH_HEADER_SIZE];
  uint8_t *netpacket_ptr = netpacket_content;

  if (bytes_to_read > HB_MAX_MTU_SIZE + HB_ETH_HEADER_SIZE) {
    HB_ERR(s, "Netpacket length is too big [%lx]\n", bytes_to_read);
    return -1;
  }

  while (bytes_to_read > 0) {
    if (bytes_to_read >= HB_BLOCK_TRANSFER_SIZE) {
      transfer_size = HB_BLOCK_TRANSFER_SIZE;
    } else {
      transfer_size = bytes_to_read;
    }

    struct HummingbirdBlockData *current_cons_desc =
      try_get_cons_desc_addr(&netpacket_from_guest_buf_attrs);

    if (!current_cons_desc) {
      HB_ERR(s,
        "Failed to get inline pointer for the egress netpacket buffer queue\n");
      rc = -1;
      break;
    }

    if (current_cons_desc->header.seq != next_buf_seq) {
      HB_ERR(s, "Netpacket seq mismatch, expected %lx, got %lx\n",
        next_buf_seq, current_cons_desc->header.seq);
      rc = -1;
      break;
    }

    memcpy(netpacket_ptr, current_cons_desc->bytes, transfer_size);
    netpacket_ptr += transfer_size;
    bytes_to_read -= transfer_size;
    next_buf_seq++;
    rc = advance_cons_and_post(&netpacket_from_guest_buf_attrs);
    if (rc) {
      HB_ERR(s,
        "Failed to enqueue the netpacket data to the queue [%s]\n",
          netpacket_to_guest_notif_attrs.qid);
      rc = -1;
      break;
    }
  }

  if (rc == 0) {
    NetClientState *queue = qemu_get_subqueue(s->nic, 0);
    if (!queue) {
      HB_ERR(s, "Failed to get the net client state for the queue\n");
      rc = -1;
    } else {
      qemu_send_packet(queue, netpacket_content, netpacket_req->netpacket_len);
    }
  } else {
    HB_ERR(s, "Failed to enqueue network packet\n");
  }

  return rc;
}

static int hb_try_exec_netpacket_ops(const struct HummingbirdState *s) {
  /* Network packets arriving from guest to be transmitted into TAP */
  struct HummingbirdNetPacketNotification netpacket_req;

  if (dequeue(&netpacket_from_guest_notif_attrs, &netpacket_req) != 0)
    return 0;

  int rc = hb_exec_netpacket_egress(s, &netpacket_req);

  if (rc) {
    HB_ERR(s, "Failed to enqueue network packet to the TAP device\n");
  }

  return rc;
}

static void *hb_consumer_thread_loop(void *arg) {
  struct HummingbirdState *s = (struct HummingbirdState *)arg;
  int rc;

  HB_INFO(s, "consumer thread started\n");

  while (s->run_consumer_thread) {
    rc = hb_try_exec_dma_ops(s);
    if (rc) {
      s->run_consumer_thread = false;
      HB_ERR(s, "stopping consumer thread loop\n");
      break;
    }

    hb_try_exec_msix_ops(s);

    rc = hb_try_exec_netpacket_ops(s);
    if (rc) {
      s->run_consumer_thread = false;
      HB_ERR(s, "stopping consumer thread loop\n");
      break;
    }
  }

  HB_ERR(s, "consumer thread loop stopped\n");
  return NULL;
}

static int hb_setup_interconnect(struct HummingbirdState *s) {
  CONNECT_QUEUE_OR_RETURN_ERROR(s, config_req_attrs, HB_CONFIG_REQ_QID_SUFFIX);
  CONNECT_QUEUE_OR_RETURN_ERROR(s, config_resp_attrs, HB_CONFIG_RESP_QID_SUFFIX);

  CONNECT_QUEUE_OR_RETURN_ERROR(s, reg_rw_req_attrs, HB_REG_RW_REQ_QID_SUFFIX);
  CONNECT_QUEUE_OR_RETURN_ERROR(s, reg_rw_resp_attrs, HB_REG_RW_RESP_QID_SUFFIX);

  CONNECT_QUEUE_OR_RETURN_ERROR(s, dma_req_attrs, HB_DMA_REQ_QID_SUFFIX);
  CONNECT_QUEUE_OR_RETURN_ERROR(s, dma_resp_attrs, HB_DMA_RESP_QID_SUFFIX);
  CONNECT_QUEUE_OR_RETURN_ERROR(s, dma_read_buf_attrs, HB_DMA_READ_BUFFER_QID_SUFFIX);
  CONNECT_QUEUE_OR_RETURN_ERROR(s, dma_write_buf_attrs, HB_DMA_WRITE_BUFFER_QID_SUFFIX);

  CONNECT_QUEUE_OR_RETURN_ERROR(s, msix_req_attrs, HB_MSIX_REQ_QID_SUFFIX);

  CONNECT_QUEUE_OR_RETURN_ERROR(s, netpacket_to_guest_notif_attrs, HB_NET_INGRESS_QID_SUFFIX);
  CONNECT_QUEUE_OR_RETURN_ERROR(s, netpacket_to_guest_buf_attrs, HB_NET_INGRESS_BUFFER_QID_SUFFIX);
  CONNECT_QUEUE_OR_RETURN_ERROR(s, netpacket_from_guest_notif_attrs, HB_NET_EGRESS_QID_SUFFIX);
  CONNECT_QUEUE_OR_RETURN_ERROR(s, netpacket_from_guest_buf_attrs, HB_NET_EGRESS_BUFFER_QID_SUFFIX);

  s->run_consumer_thread = true;
  qemu_thread_create(&s->consumer_thread, "hb_consumer_thread",
    hb_consumer_thread_loop, s, PTHREAD_CREATE_JOINABLE);
  HB_INFO(s, "Created the consumer thread\n");

  return 0;
}

static int hb_reset_interconnect(struct HummingbirdState *s) {
  s->run_consumer_thread = false;
  int err;
  void *ret;
  err = pthread_join(s->consumer_thread.thread, &ret);
  if (err == ESRCH) {
    return -1;
  }
  if (err) {
    HB_ERR(s, "Failed to join the consumer thread: %s\n", strerror(err));
    abort();
  }

  destroy_queue(&config_req_attrs);
  destroy_queue(&config_resp_attrs);
  destroy_queue(&reg_rw_req_attrs);
  destroy_queue(&reg_rw_resp_attrs);
  destroy_queue(&dma_req_attrs);
  destroy_queue(&dma_resp_attrs);
  destroy_queue(&dma_read_buf_attrs);
  destroy_queue(&dma_write_buf_attrs);
  destroy_queue(&msix_req_attrs);
  destroy_queue(&netpacket_to_guest_notif_attrs);
  destroy_queue(&netpacket_to_guest_buf_attrs);
  destroy_queue(&netpacket_from_guest_notif_attrs);
  destroy_queue(&netpacket_from_guest_buf_attrs);

  return 0;
}

static int hb_request_config(
  struct HummingbirdState *s, struct HummingbirdConfigResponse *response) {
  int rc;
  static uint64_t next_sequence = 1;
  struct HummingbirdConfigRequest request = {
    .header = {
      .seq = next_sequence++,
    },
  };

  rc = enqueue(&config_req_attrs, (uint8_t *)&request);
  if (rc != 0) {
    HB_ERR(s, "Failed to write the config request to the model backend.\n");
    return -1;
  }

  HB_INFO(s, "Reading the config from the model backend.\n");
  rc = dequeue(&config_resp_attrs, (uint8_t *)response);

  while (rc == -EAGAIN) {
    HB_INFO(s, "Waiting for the config from the model backend.\n");
    sleep(1);
    rc = dequeue(&config_resp_attrs, (uint8_t *)response);
  }

  if (rc != 0) {
    HB_ERR(s, "Failed to read the config from the model backend.\n");
    return -1;
  }

  if (response->completion.header.seq != request.header.seq) {
    HB_ERR(s, "Sequence mismatch, expected:%ld, got:%ld\n",
      request.header.seq, response->completion.header.seq);
    return -1;
  }

  HB_INFO(s, "Read the config from the model backend.\n");

  return 0;
}

static void hb_pci_realize(PCIDevice *pci_dev, Error **errp) {

  struct HummingbirdState *s = HUMMINGBIRD(pci_dev);

  HB_INFO(s, "Initializing the instance with devfn %d\n", pci_dev->devfn);

  if (!s->qid_prefix || strlen(s->qid_prefix) == 0) {
    HB_ERR(s, "Model interconnect sparrow queue prefix is not defined\n");
    exit(1);
  }

  if (hb_setup_interconnect(s) != 0) {
    HB_ERR(s, "Failed to connect to the model backend.\n");
    exit(1);
  }

  struct HummingbirdConfigResponse pcie_config = {0};

  if (hb_request_config(s, &pcie_config) != 0) {
    HB_ERR(s, "Failed to read the config from the model backend.\n");
    exit(1);
  }

  if (!s->subsys_ven)
    s->subsys_ven = pcie_config.subsys_vendor_id;
  if (!s->subsys)
    s->subsys = pcie_config.subsys_id;

  if (s->subsys_ven == 0 || s->subsys == 0) {
    HB_ERR(s, "subsys_ven and subsys must be set.\n");
    exit(1);
  }

  pci_set_word(pci_dev->config + PCI_VENDOR_ID, s->subsys_ven);
  pci_set_word(pci_dev->config + PCI_DEVICE_ID, s->subsys);

  pci_dev->config_write = hb_write_config;

  pci_dev->config[PCI_CACHE_LINE_SIZE] = 0x10;
  pci_dev->config[PCI_INTERRUPT_PIN] = 1;

  pci_set_word(pci_dev->config + PCI_SUBSYSTEM_VENDOR_ID, s->subsys_ven);
  pci_set_word(pci_dev->config + PCI_SUBSYSTEM_ID, s->subsys);

  s->pci_id = pci_get_word(pci_dev->config + PCI_DEVICE_ID);

  s->subsys_ven_used = s->subsys_ven;
  s->subsys_used = s->subsys;

  s->bar[0].size = pcie_config.bar0_size;
  s->bar[0].prefetch = pcie_config.bar0_prefetchable;
  s->bar[2].size = pcie_config.bar2_size;
  s->bar[2].prefetch = pcie_config.bar2_prefetchable;
  s->bar[4].size = pcie_config.bar4_size;
  s->bar[4].prefetch = pcie_config.bar4_prefetchable;

  for (int bar_index = 0; bar_index < 6; bar_index += 2) {
    char bar_name[16] = {0};
    snprintf(bar_name, sizeof(bar_name) - 1, "pcie-bar%d-msix", bar_index);
    if (pcie_config.msix_index == bar_index) {
      memory_region_init(&s->bar[bar_index].bar, OBJECT(s),
                         bar_name, s->bar[bar_index].size);
    } else {
      memory_region_init_io(&s->bar[bar_index].bar, OBJECT(s),
                            &hb_bar_ops[bar_index], s, bar_name,
                            s->bar[bar_index].size);
    }
    uint8_t attributes = PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64;
    if (s->bar[bar_index].prefetch) {
        attributes |= PCI_BASE_ADDRESS_MEM_PREFETCH;
    }
    pci_register_bar(
        pci_dev, bar_index,
        attributes,
        &s->bar[bar_index].bar);
  }

  /* Create networking backend */
  memcpy(&s->conf.macaddr, pcie_config.mac, sizeof(s->conf.macaddr));
  qemu_macaddr_default_if_unset(&s->conf.macaddr);
  memcpy(s->mac, s->conf.macaddr.a, sizeof(s->mac));

  if (pcie_endpoint_cap_init(pci_dev, pcie_config.pcie_offset) < 0)
    hw_error("Failed to initialize PCIe capability");

  hb_init_msix(s, &pcie_config);

  if (hb_add_pm_capability(pci_dev, pcie_config.pmrb_offset, PCI_PM_CAP_DSI) <
      0)
    hw_error("Failed to initialize PM capability");

  pcie_cap_deverr_init(pci_dev);
  if (pcie_aer_init(pci_dev, PCI_ERR_VER, pcie_config.aer_offset, PCI_ERR_SIZEOF,
                    NULL) < 0)
    hw_error("Failed to initialize AER capability");

  hb_pcie_ari_init(pci_dev, pcie_config.ari_offset,
                        pci_dev->devfn + pcie_config.ari_increment);

  pcie_dev_ser_num_init(pci_dev, pcie_config.dsn_offset, hb_gen_dsn(s->mac));

  s->nic = qemu_new_nic(&net_hb_mac_info, &s->conf,
    object_get_typename(OBJECT(s)), object_get_typename(OBJECT(s)), NULL, s);

  hb_format_nic_info_str(qemu_get_queue(s->nic), "mac", s->mac);

  HB_INFO(s, "Hummingbird device is materialized\n");
}

static void hb_pci_uninit(PCIDevice *pci_dev) {
  struct HummingbirdState *s = HUMMINGBIRD(pci_dev);

  hb_reset_interconnect(s);

  pcie_aer_exit(pci_dev);
  pcie_cap_exit(pci_dev);
  hb_cleanup_msix(s);

  qemu_del_nic(s->nic);
}

static void hb_qdev_reset(DeviceState *dev) {}

static int hb_pre_save(void *opaque) { return 0; }

static int hb_post_load(void *opaque, int version_id) {
  struct HummingbirdState *s = (struct HummingbirdState *)opaque;

  if ((s->subsys != s->subsys_used) || (s->subsys_ven != s->subsys_ven_used))
    hw_error("ERROR: Cannot migrate while device properties "
             "(subsys/subsys_ven) differ\n");

  return 0;
}

static const VMStateDescription hb_vmstate = {
    .name = "hummingbird",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = hb_pre_save,
    .post_load = hb_post_load,
    .fields = (VMStateField[]){VMSTATE_PCI_DEVICE(parent_obj, HummingbirdState),
                               VMSTATE_MSIX(parent_obj, HummingbirdState),
                               VMSTATE_UINT16(subsys, HummingbirdState),
                               VMSTATE_UINT16(subsys_ven, HummingbirdState),
                               VMSTATE_END_OF_LIST()}};

static PropertyInfo hb_prop_subsys_ven, hb_prop_subsys;

static Property hb_properties[] = {
    DEFINE_NIC_PROPERTIES(HummingbirdState, conf),
    DEFINE_PROP_STRING("qid_prefix", HummingbirdState, qid_prefix),
    DEFINE_PROP_SIGNED("subsys_ven", HummingbirdState, subsys_ven, 0,
                       hb_prop_subsys_ven, uint16_t),
    DEFINE_PROP_SIGNED("subsys", HummingbirdState, subsys, 0, hb_prop_subsys,
                       uint16_t),
    DEFINE_PROP_END_OF_LIST(),
};

static void hb_class_init(ObjectClass *class, void *data) {
  DeviceClass *dc = DEVICE_CLASS(class);
  PCIDeviceClass *c = PCI_DEVICE_CLASS(class);
  c->realize = hb_pci_realize;
  c->exit = hb_pci_uninit;
  c->vendor_id = 0;
  c->device_id = 0;
  c->revision = 0;
  c->class_id = PCI_CLASS_NETWORK_ETHERNET;

  dc->desc = "Hummingbird PCIe pass-through";
  dc->reset = hb_qdev_reset;
  dc->vmsd = &hb_vmstate;

  hb_prop_subsys_ven = qdev_prop_uint16;
  hb_prop_subsys_ven.description = "PCI device Subsystem Vendor ID";

  hb_prop_subsys = qdev_prop_uint16;
  hb_prop_subsys.description = "PCI device Subsystem ID";

  device_class_set_props(dc, hb_properties);
  set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}

static void hb_instance_init(/* HummingbirdState */ Object *obj) {}
static void hb_instance_finalize(/* HummingbirdState */ Object *obj) {}

static const TypeInfo hb_info = {
    .name = TYPE_HUMMINGBIRD,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(struct HummingbirdState),
    .class_init = hb_class_init,
    .instance_init = hb_instance_init,
    .instance_finalize = hb_instance_finalize,
    .interfaces = (InterfaceInfo[]){{INTERFACE_PCIE_DEVICE}, {}},
};

static void hb_register_types(void) {
  type_register_static(&hb_info);
}

type_init(hb_register_types)
