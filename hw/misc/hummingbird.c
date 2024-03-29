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
} HummingbirdState;

#define TYPE_HUMMINGBIRD "hummingbird"
#define HUMMINGBIRD(obj) OBJECT_CHECK(HummingbirdState, (obj), TYPE_HUMMINGBIRD)

static void hummingbird_write_config(PCIDevice *pci_dev, uint32_t address,
                                 uint32_t val, int len) {
  pci_default_write_config(pci_dev, address, val, len);
}

static void hummingbird_unuse_msix_vectors(HummingbirdState *s) {
  for (int i = 0; i < s->msix_num_vectors; ++i)
    msix_vector_unuse(PCI_DEVICE(s), i);
}

static void hummingbird_use_msix_vectors(HummingbirdState *s) {
  for (int i = 0; i < s->msix_num_vectors; ++i) {
    fprintf(stderr, "Hummingbird: Using MSI-X vector %d/%d out of %d\n", i, s->msix_num_vectors, PCI_DEVICE(s)->msix_entries_nr);
    msix_vector_use(PCI_DEVICE(s), i);
  }
}

static void hummingbird_init_msix(HummingbirdState *s, struct HummingbirdConfigResponse *config) {
  PCIDevice *d = PCI_DEVICE(s);
  struct Error *err = 0;
  s->msix_index = config->msix_index;
  s->msix_num_vectors = config->msix_num_vectors;

  fprintf(stderr,
          "s->msix_num_vectors = %d, s->msix_index = %d, config->msix_pba_bar_nr = %d, config->msix_pba_offset = %d, config->msix_cap_pos = %d\n",
          s->msix_num_vectors, s->msix_index, config->msix_pba_bar_nr, config->msix_pba_offset, config->msix_cap_pos);

  int res =
      msix_init(d, s->msix_num_vectors, &s->bar[s->msix_index].bar,
                s->msix_index, /* MSIX TABLE */0, &s->bar[s->msix_index].bar,
                config->msix_pba_bar_nr, config->msix_pba_offset, config->msix_cap_pos, &err);

  if (res >= 0) {
    hummingbird_use_msix_vectors(s);
    return;
  }

  fprintf(stderr, "Hummingbird: Failed to use MSI-X vectors\n");
}

static void hummingbird_cleanup_msix(HummingbirdState *s) {
  if (msix_present(PCI_DEVICE(s))) {
    hummingbird_unuse_msix_vectors(s);
    msix_uninit(PCI_DEVICE(s), &s->bar[s->msix_index].bar,
                &s->bar[s->msix_index].bar);
  }
}

static inline uint64_t hummingbird_read(void *opaque, int bar_index, hwaddr addr,
                                    unsigned size) {
  /* TBD */
  return 0;
}

static inline void hummingbird_write(void *opaque, int bar_index, hwaddr addr,
                                 uint64_t val, unsigned size) {
  /* TBD */
}

static uint64_t hummingbird_bar0_read(void *opaque, hwaddr addr, unsigned size) {
  return hummingbird_read(opaque, 0, addr, size);
}

static uint64_t hummingbird_bar2_read(void *opaque, hwaddr addr, unsigned size) {
  return hummingbird_read(opaque, 2, addr, size);
}

static uint64_t hummingbird_bar4_read(void *opaque, hwaddr addr, unsigned size) {
  return hummingbird_read(opaque, 4, addr, size);
}

static void hummingbird_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  hummingbird_write(opaque, 0, addr, val, size);
}

static void hummingbird_bar2_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  hummingbird_write(opaque, 2, addr, val, size);
}

static void hummingbird_bar4_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  hummingbird_write(opaque, 4, addr, val, size);
}

static const MemoryRegionOps hummingbird_bar_ops[6] = {
    {
        .read = hummingbird_bar0_read,
        .write = hummingbird_bar0_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
    {
        .read = hummingbird_bar2_read,
        .write = hummingbird_bar2_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
    {
        .read = hummingbird_bar4_read,
        .write = hummingbird_bar4_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
};

static int hummingbird_add_pm_capability(PCIDevice *pdev, uint8_t offset,
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
static void hummingbird_pcie_ari_init(PCIDevice *dev, uint16_t offset,
                                  uint8_t nextfn) {
  if (!(dev->cap_present & QEMU_PCIE_ARI_NEXTFN_1)) {
    nextfn = 0;
  }

  pcie_add_capability(dev, PCI_EXT_CAP_ID_ARI, PCI_ARI_VER, offset,
                      PCI_ARI_SIZEOF);
  pci_set_long(dev->config + offset + PCI_ARI_CAP, (nextfn & 0xff) << 8);
}

static void hummingbird_set_link_status(NetClientState* nc) {
  HummingbirdState* s = (HummingbirdState*)qemu_get_nic_opaque(nc);
  uint8_t stale_link = s->link;
  s->link = !nc->link_down;
  if (s->link != stale_link) {
    fprintf(stderr,
        "OWLNIC link status changed %s => %s\n",
        stale_link ? "UP" : "DOWN",
        s->link ? "UP" : "DOWN");
  }
}

static bool hummingbird_can_receive(NetClientState *nc) { return TRUE; }

static ssize_t hummingbird_receive_iov(NetClientState *nc, const struct iovec *iov,
                            int iovcnt) {
  ssize_t total = iov_size(iov, iovcnt);

  /* Transmit received frame to the model */

  return total;
}

static ssize_t hummingbird_receive(NetClientState *nc, const uint8_t *buf, size_t size) {
  const struct iovec iov = {.iov_base = (uint8_t *)buf, .iov_len = size};
  return hummingbird_receive_iov(nc, &iov, 1);
}

static NetClientInfo net_hummingbird_mac_info = {.type = NET_CLIENT_DRIVER_NIC,
                                            .size = sizeof(NICState),
                                            .can_receive = hummingbird_can_receive,
                                            .receive = hummingbird_receive,
                                            .receive_iov = hummingbird_receive_iov,
                                            .link_status_changed =
                                                hummingbird_set_link_status};

static inline uint64_t hummingbird_gen_dsn(uint8_t *mac) {
  return (uint64_t)(mac[5]) | (uint64_t)(mac[4]) << 8 |
         (uint64_t)(mac[3]) << 16 | (uint64_t)(0x00FF) << 24 |
         (uint64_t)(0x00FF) << 32 | (uint64_t)(mac[2]) << 40 |
         (uint64_t)(mac[1]) << 48 | (uint64_t)(mac[0]) << 56;
}

static void hummingbird_format_nic_info_str(NetClientState *nc, const char *type,
                                       uint8_t macaddr[6]) {
  snprintf(nc->info_str, sizeof(nc->info_str),
           "model=%s,type=%s,macaddr=%02x:%02x:%02x:%02x:%02x:%02x", nc->model,
           type, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4],
           macaddr[5]);
}

struct QueueAttrs config_attrs = {
  .qid = "conf",
  .desc_size = sizeof(struct HummingbirdConfigRequest),
  .num_descs = 8,
  .last_cons = 0,
  .last_prod = 0,
  .is_a_producer = true,
};

struct QueueAttrs config_cmpl_attrs = {
  .qid = "conf_cmpl",
  .desc_size = sizeof(struct HummingbirdConfigResponse),
  .num_descs = 8,
  .last_cons = 0,
  .last_prod = 0,
  .is_a_producer = false,
};

static int hummingbird_connect_model_backend(struct HummingbirdState *s) {
  int rc = connect_queue(&config_attrs, 10);
  if (rc) {
    fprintf(stderr, "ERROR: Failed to connect to the config queue.\n");
    return -1;
  }
  rc = connect_queue(&config_cmpl_attrs, 10);
  if (rc) {
    fprintf(stderr, "ERROR: Failed to connect to the config completion queue.\n");
  }

  return 0;
}

static int hummingbird_disconnect_model_backend(struct HummingbirdState *s) {
  destroy_queue(&config_attrs);
  destroy_queue(&config_cmpl_attrs);

  return 0;
}

static int hummingbird_request_config(
  struct HummingbirdState *s, struct HummingbirdConfigResponse *response) {
  int rc;
  static uint64_t next_sequence = 1;
  struct HummingbirdConfigRequest request = {
    .header = {
      .sequence = next_sequence++,
    },
  };

  rc = enqueue(&config_attrs, (uint8_t *)&request);
  if (rc != 0) {
    fprintf(stderr, "ERROR: Failed to write the config request to the model backend.\n");
    return -1;
  }

  fprintf(stderr, "Reading the config from the model backend.\n");
  rc = dequeue(&config_cmpl_attrs, (uint8_t *)response);

  while (rc == -EAGAIN) {
    fprintf(stderr, "Waiting for the config from the model backend.\n");
    sleep(1);
    rc = dequeue(&config_cmpl_attrs, (uint8_t *)response);
  }

  if (rc != 0) {
    fprintf(stderr, "ERROR: Failed to read the config from the model backend.\n");
    return -1;
  }

  if (response->completion.header.sequence != request.header.sequence) {
    fprintf(stderr, "ERROR: Sequence mismatch, expected:%ld, got:%ld\n",
      request.header.sequence, response->completion.header.sequence);
    return -1;
  }

  fprintf(stderr, "Read the config from the model backend.\n");

  return 0;
}

static void hummingbird_pci_realize(PCIDevice *pci_dev, Error **errp) {

  HummingbirdState *s = HUMMINGBIRD(pci_dev);

  fprintf(stderr, "Initializing the instance with devfn %d\n", pci_dev->devfn);

  if (hummingbird_connect_model_backend(s) != 0) {
    fprintf(stderr, "ERROR: Failed to connect to the model backend.\n");
    exit(1);
  }

  struct HummingbirdConfigResponse pcie_config = {0};

  if (hummingbird_request_config(s, &pcie_config) != 0) {
    fprintf(stderr, "ERROR: Failed to read the config from the model backend.\n");
    exit(1);
  }

  if (!s->subsys_ven)
    s->subsys_ven = pcie_config.subsys_vendor_id;
  if (!s->subsys)
    s->subsys = pcie_config.subsys_id;

  if (s->subsys_ven == 0 || s->subsys == 0) {
    fprintf(stderr, "ERROR: subsys_ven and subsys must be set.\n");
    exit(1);
  }

  pci_set_word(pci_dev->config + PCI_VENDOR_ID, s->subsys_ven);
  pci_set_word(pci_dev->config + PCI_DEVICE_ID, s->subsys);

  pci_dev->config_write = hummingbird_write_config;

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
                            &hummingbird_bar_ops[bar_index], s, bar_name,
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

  hummingbird_init_msix(s, &pcie_config);

  if (hummingbird_add_pm_capability(pci_dev, pcie_config.pmrb_offset, PCI_PM_CAP_DSI) <
      0)
    hw_error("Failed to initialize PM capability");

  pcie_cap_deverr_init(pci_dev);
  if (pcie_aer_init(pci_dev, PCI_ERR_VER, pcie_config.aer_offset, PCI_ERR_SIZEOF,
                    NULL) < 0)
    hw_error("Failed to initialize AER capability");

  hummingbird_pcie_ari_init(pci_dev, pcie_config.ari_offset,
                        pci_dev->devfn + pcie_config.ari_increment);

  pcie_dev_ser_num_init(pci_dev, pcie_config.dsn_offset, hummingbird_gen_dsn(s->mac));

  s->nic = qemu_new_nic(&net_hummingbird_mac_info, &s->conf, object_get_typename(OBJECT(s)), object_get_typename(OBJECT(s)), NULL, s);

  hummingbird_format_nic_info_str(qemu_get_queue(s->nic), "mac", s->mac);

  fprintf(stderr, "Hummingbird device is materialized\n");
}

static void hummingbird_pci_uninit(PCIDevice *pci_dev) {
  HummingbirdState *s = HUMMINGBIRD(pci_dev);

  hummingbird_disconnect_model_backend(s);

  pcie_aer_exit(pci_dev);
  pcie_cap_exit(pci_dev);
  hummingbird_cleanup_msix(s);

  qemu_del_nic(s->nic);
}

static void hummingbird_qdev_reset(DeviceState *dev) {}

static int hummingbird_pre_save(void *opaque) { return 0; }

static int hummingbird_post_load(void *opaque, int version_id) {
  HummingbirdState *s = (HummingbirdState *)opaque;

  if ((s->subsys != s->subsys_used) || (s->subsys_ven != s->subsys_ven_used))
    hw_error("ERROR: Cannot migrate while device properties "
             "(subsys/subsys_ven) differ\n");

  return 0;
}

static const VMStateDescription hummingbird_vmstate = {
    .name = "hummingbird",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = hummingbird_pre_save,
    .post_load = hummingbird_post_load,
    .fields = (VMStateField[]){VMSTATE_PCI_DEVICE(parent_obj, HummingbirdState),
                               VMSTATE_MSIX(parent_obj, HummingbirdState),
                               VMSTATE_UINT16(subsys, HummingbirdState),
                               VMSTATE_UINT16(subsys_ven, HummingbirdState),
                               VMSTATE_END_OF_LIST()}};

static PropertyInfo hummingbird_prop_subsys_ven, hummingbird_prop_subsys;

static Property hummingbird_properties[] = {
    DEFINE_NIC_PROPERTIES(HummingbirdState, conf),
    DEFINE_PROP_STRING("qid_prefix", HummingbirdState, qid_prefix),
    DEFINE_PROP_SIGNED("subsys_ven", HummingbirdState, subsys_ven, 0,
                       hummingbird_prop_subsys_ven, uint16_t),
    DEFINE_PROP_SIGNED("subsys", HummingbirdState, subsys, 0, hummingbird_prop_subsys,
                       uint16_t),
    DEFINE_PROP_END_OF_LIST(),
};

static void hummingbird_class_init(ObjectClass *class, void *data) {
  DeviceClass *dc = DEVICE_CLASS(class);
  PCIDeviceClass *c = PCI_DEVICE_CLASS(class);
  c->realize = hummingbird_pci_realize;
  c->exit = hummingbird_pci_uninit;
  c->vendor_id = 0;
  c->device_id = 0;
  c->revision = 0;
  c->class_id = PCI_CLASS_NETWORK_ETHERNET;

  dc->desc = "Hummingbird PCIe pass-through";
  dc->reset = hummingbird_qdev_reset;
  dc->vmsd = &hummingbird_vmstate;

  hummingbird_prop_subsys_ven = qdev_prop_uint16;
  hummingbird_prop_subsys_ven.description = "PCI device Subsystem Vendor ID";

  hummingbird_prop_subsys = qdev_prop_uint16;
  hummingbird_prop_subsys.description = "PCI device Subsystem ID";

  device_class_set_props(dc, hummingbird_properties);
  set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}

static void hummingbird_instance_init(/* HummingbirdState */ Object *obj) {}
static void hummingbird_instance_finalize(/* HummingbirdState */ Object *obj) {}

static const TypeInfo hummingbird_info = {
    .name = TYPE_HUMMINGBIRD,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(HummingbirdState),
    .class_init = hummingbird_class_init,
    .instance_init = hummingbird_instance_init,
    .instance_finalize = hummingbird_instance_finalize,
    .interfaces = (InterfaceInfo[]){{INTERFACE_PCIE_DEVICE}, {}},
};

static void hummingbird_register_types(void) {
  type_register_static(&hummingbird_info);
}

type_init(hummingbird_register_types)
