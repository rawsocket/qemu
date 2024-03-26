/*
 * Phoenix: A pass-though PCIE device to allow external hardware models.
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

#include "hw/misc/phoenix.h"
#include "hw/misc/queue.h"

struct BarConfig {
  struct MemoryRegion bar;
  uint32_t size;
  bool prefetch;
};

typedef struct PhoenixState {
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
} PhoenixState;

#define TYPE_PHOENIX "phoenix"
#define PHOENIX(obj) OBJECT_CHECK(PhoenixState, (obj), TYPE_PHOENIX)

static void phoenix_write_config(PCIDevice *pci_dev, uint32_t address,
                                 uint32_t val, int len) {
  pci_default_write_config(pci_dev, address, val, len);
}

static void phoenix_unuse_msix_vectors(PhoenixState *s) {
  for (int i = 0; i < s->msix_num_vectors; ++i)
    msix_vector_unuse(PCI_DEVICE(s), i);
}

static void phoenix_use_msix_vectors(PhoenixState *s) {
  for (int i = 0; i < s->msix_num_vectors; ++i) {
    fprintf(stderr, "Phoenix: Using MSI-X vector %d/%d out of %d\n", i, s->msix_num_vectors, PCI_DEVICE(s)->msix_entries_nr);
    msix_vector_use(PCI_DEVICE(s), i);
  }
}

static void phoenix_init_msix(PhoenixState *s, struct phoenix_config_db *config) {
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
    phoenix_use_msix_vectors(s);
    return;
  }

  fprintf(stderr, "Phoenix: Failed to use MSI-X vectors\n");
}

static void phoenix_cleanup_msix(PhoenixState *s) {
  if (msix_present(PCI_DEVICE(s))) {
    phoenix_unuse_msix_vectors(s);
    msix_uninit(PCI_DEVICE(s), &s->bar[s->msix_index].bar,
                &s->bar[s->msix_index].bar);
  }
}

static inline uint64_t phoenix_read(void *opaque, int bar_index, hwaddr addr,
                                    unsigned size) {
  /* TBD */
  return 0;
}

static inline void phoenix_write(void *opaque, int bar_index, hwaddr addr,
                                 uint64_t val, unsigned size) {
  /* TBD */
}

static uint64_t phoenix_bar0_read(void *opaque, hwaddr addr, unsigned size) {
  return phoenix_read(opaque, 0, addr, size);
}

static uint64_t phoenix_bar2_read(void *opaque, hwaddr addr, unsigned size) {
  return phoenix_read(opaque, 2, addr, size);
}

static uint64_t phoenix_bar4_read(void *opaque, hwaddr addr, unsigned size) {
  return phoenix_read(opaque, 4, addr, size);
}

static void phoenix_bar0_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  phoenix_write(opaque, 0, addr, val, size);
}

static void phoenix_bar2_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  phoenix_write(opaque, 2, addr, val, size);
}

static void phoenix_bar4_write(void *opaque, hwaddr addr, uint64_t val,
                               unsigned size) {
  phoenix_write(opaque, 4, addr, val, size);
}

static const MemoryRegionOps phoenix_bar_ops[6] = {
    {
        .read = phoenix_bar0_read,
        .write = phoenix_bar0_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
    {
        .read = phoenix_bar2_read,
        .write = phoenix_bar2_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
    {
        .read = phoenix_bar4_read,
        .write = phoenix_bar4_write,
        .endianness = DEVICE_LITTLE_ENDIAN,
        .impl =
            {
                .min_access_size = 4,
                .max_access_size = 4,
            },
    },
    {0},
};

static int phoenix_add_pm_capability(PCIDevice *pdev, uint8_t offset,
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
static void phoenix_pcie_ari_init(PCIDevice *dev, uint16_t offset,
                                  uint8_t nextfn) {
  if (!(dev->cap_present & QEMU_PCIE_ARI_NEXTFN_1)) {
    nextfn = 0;
  }

  pcie_add_capability(dev, PCI_EXT_CAP_ID_ARI, PCI_ARI_VER, offset,
                      PCI_ARI_SIZEOF);
  pci_set_long(dev->config + offset + PCI_ARI_CAP, (nextfn & 0xff) << 8);
}

static void phoenix_set_link_status(NetClientState* nc) {
  PhoenixState* s = (PhoenixState*)qemu_get_nic_opaque(nc);
  uint8_t stale_link = s->link;
  s->link = !nc->link_down;
  if (s->link != stale_link) {
    fprintf(stderr,
        "OWLNIC link status changed %s => %s\n",
        stale_link ? "UP" : "DOWN",
        s->link ? "UP" : "DOWN");
  }
}

static bool phoenix_can_receive(NetClientState *nc) { return TRUE; }

static ssize_t phoenix_receive_iov(NetClientState *nc, const struct iovec *iov,
                            int iovcnt) {
  ssize_t total = iov_size(iov, iovcnt);

  /* Transmit received frame to the model */

  return total;
}

static ssize_t phoenix_receive(NetClientState *nc, const uint8_t *buf, size_t size) {
  const struct iovec iov = {.iov_base = (uint8_t *)buf, .iov_len = size};
  return phoenix_receive_iov(nc, &iov, 1);
}

static NetClientInfo net_phoenix_mac_info = {.type = NET_CLIENT_DRIVER_NIC,
                                            .size = sizeof(NICState),
                                            .can_receive = phoenix_can_receive,
                                            .receive = phoenix_receive,
                                            .receive_iov = phoenix_receive_iov,
                                            .link_status_changed =
                                                phoenix_set_link_status};

static inline uint64_t phoenix_gen_dsn(uint8_t *mac) {
  return (uint64_t)(mac[5]) | (uint64_t)(mac[4]) << 8 |
         (uint64_t)(mac[3]) << 16 | (uint64_t)(0x00FF) << 24 |
         (uint64_t)(0x00FF) << 32 | (uint64_t)(mac[2]) << 40 |
         (uint64_t)(mac[1]) << 48 | (uint64_t)(mac[0]) << 56;
}

static void phoenix_format_nic_info_str(NetClientState *nc, const char *type,
                                       uint8_t macaddr[6]) {
  snprintf(nc->info_str, sizeof(nc->info_str),
           "model=%s,type=%s,macaddr=%02x:%02x:%02x:%02x:%02x:%02x", nc->model,
           type, macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4],
           macaddr[5]);
}

struct QueueAttrs config_attrs = {
  .qid = "conf",
  .desc_size = sizeof(struct phoenix_config_db),
  .num_descs = 8,
  .last_cons = 0,
  .last_prod = 0,
  .is_a_producer = false,
};

struct QueueAttrs config_cmpl_attrs = {
  .qid = "conf.cmpl",
  .desc_size = sizeof(struct phoenix_completion),
  .num_descs = 8,
  .last_cons = 0,
  .last_prod = 0,
  .is_a_producer = true,
};

static int phoenix_connect_model_backend(struct PhoenixState *s) {
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

static int phoenix_disconnect_model_backend(struct PhoenixState *s) {
  destroy_queue(&config_attrs);
  destroy_queue(&config_cmpl_attrs);

  return 0;
}

static int phoenix_read_config(struct PhoenixState *s, struct phoenix_config_db *pcie_config) {
  int rc;

  fprintf(stderr, "Reading the config from the model backend.\n");
  rc = dequeue(&config_attrs, (uint8_t *)pcie_config);

  while (rc == -EAGAIN) {
    fprintf(stderr, "Waiting for the config from the model backend.\n");
    sleep(1);
    rc = dequeue(&config_attrs, (uint8_t *)pcie_config);
  }

  if (rc != 0) {
    fprintf(stderr, "ERROR: Failed to read the config from the model backend.\n");
    return -1;
  }

  fprintf(stderr, "Read the config from the model backend.\n");

  return 0;
}

static void phoenix_pci_realize(PCIDevice *pci_dev, Error **errp) {

  PhoenixState *s = PHOENIX(pci_dev);

  fprintf(stderr, "Initializing the instance with devfn %d\n", pci_dev->devfn);

  if (phoenix_connect_model_backend(s) != 0) {
    hw_error("ERROR: Failed to connect to the model backend.\n");
  }

  struct phoenix_config_db pcie_config = {0};

  if (phoenix_read_config(s, &pcie_config) != 0) {
    hw_error("ERROR: Failed to read the config from the model backend.\n");
  }

  if (!s->subsys_ven)
    s->subsys_ven = pcie_config.subsys_vendor_id;
  if (!s->subsys)
    s->subsys = pcie_config.subsys_id;

  if (s->subsys_ven == 0 || s->subsys == 0)
    hw_error("ERROR: subsys_ven and subsys must be set.\n");

  pci_set_word(pci_dev->config + PCI_VENDOR_ID, s->subsys_ven);
  pci_set_word(pci_dev->config + PCI_DEVICE_ID, s->subsys);

  pci_dev->config_write = phoenix_write_config;

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
                            &phoenix_bar_ops[bar_index], s, bar_name,
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
  qemu_macaddr_default_if_unset(&s->conf.macaddr);
  memcpy(s->mac, s->conf.macaddr.a, sizeof(s->mac));

  if (pcie_endpoint_cap_init(pci_dev, pcie_config.pcie_offset) < 0)
    hw_error("Failed to initialize PCIe capability");

  phoenix_init_msix(s, &pcie_config);

  if (phoenix_add_pm_capability(pci_dev, pcie_config.pmrb_offset, PCI_PM_CAP_DSI) <
      0)
    hw_error("Failed to initialize PM capability");

  pcie_cap_deverr_init(pci_dev);
  if (pcie_aer_init(pci_dev, PCI_ERR_VER, pcie_config.aer_offset, PCI_ERR_SIZEOF,
                    NULL) < 0)
    hw_error("Failed to initialize AER capability");

  phoenix_pcie_ari_init(pci_dev, pcie_config.ari_offset,
                        pci_dev->devfn + pcie_config.ari_increment);

  pcie_dev_ser_num_init(pci_dev, pcie_config.dsn_offset, phoenix_gen_dsn(s->mac));

  s->nic = qemu_new_nic(&net_phoenix_mac_info, &s->conf, object_get_typename(OBJECT(s)), object_get_typename(OBJECT(s)), NULL, s);

  phoenix_format_nic_info_str(qemu_get_queue(s->nic), "mac", s->mac);

  fprintf(stderr, "Phoenix device is materialized\n");
}

static void phoenix_pci_uninit(PCIDevice *pci_dev) {
  PhoenixState *s = PHOENIX(pci_dev);

  phoenix_disconnect_model_backend(s);

  pcie_aer_exit(pci_dev);
  pcie_cap_exit(pci_dev);
  phoenix_cleanup_msix(s);

  qemu_del_nic(s->nic);
}

static void phoenix_qdev_reset(DeviceState *dev) {}

static int phoenix_pre_save(void *opaque) { return 0; }

static int phoenix_post_load(void *opaque, int version_id) {
  PhoenixState *s = (PhoenixState *)opaque;

  if ((s->subsys != s->subsys_used) || (s->subsys_ven != s->subsys_ven_used))
    hw_error("ERROR: Cannot migrate while device properties "
             "(subsys/subsys_ven) differ\n");

  return 0;
}

static const VMStateDescription phoenix_vmstate = {
    .name = "phoenix",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_save = phoenix_pre_save,
    .post_load = phoenix_post_load,
    .fields = (VMStateField[]){VMSTATE_PCI_DEVICE(parent_obj, PhoenixState),
                               VMSTATE_MSIX(parent_obj, PhoenixState),
                               VMSTATE_UINT16(subsys, PhoenixState),
                               VMSTATE_UINT16(subsys_ven, PhoenixState),
                               VMSTATE_END_OF_LIST()}};

static PropertyInfo phoenix_prop_subsys_ven, phoenix_prop_subsys;

static Property phoenix_properties[] = {
    DEFINE_NIC_PROPERTIES(PhoenixState, conf),
    DEFINE_PROP_SIGNED("subsys_ven", PhoenixState, subsys_ven, 0,
                       phoenix_prop_subsys_ven, uint16_t),
    DEFINE_PROP_SIGNED("subsys", PhoenixState, subsys, 0, phoenix_prop_subsys,
                       uint16_t),
    DEFINE_PROP_END_OF_LIST(),
};

static void phoenix_class_init(ObjectClass *class, void *data) {
  DeviceClass *dc = DEVICE_CLASS(class);
  PCIDeviceClass *c = PCI_DEVICE_CLASS(class);
  c->realize = phoenix_pci_realize;
  c->exit = phoenix_pci_uninit;
  c->vendor_id = 0;
  c->device_id = 0;
  c->revision = 0;
  c->class_id = PCI_CLASS_NETWORK_ETHERNET;

  dc->desc = "Phoenix PCIe pass-through";
  dc->reset = phoenix_qdev_reset;
  dc->vmsd = &phoenix_vmstate;

  phoenix_prop_subsys_ven = qdev_prop_uint16;
  phoenix_prop_subsys_ven.description = "PCI device Subsystem Vendor ID";

  phoenix_prop_subsys = qdev_prop_uint16;
  phoenix_prop_subsys.description = "PCI device Subsystem ID";

  device_class_set_props(dc, phoenix_properties);
  set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
}

static void phoenix_instance_init(/* PhoenixState */ Object *obj) {}
static void phoenix_instance_finalize(/* PhoenixState */ Object *obj) {}

static const TypeInfo phoenix_info = {
    .name = TYPE_PHOENIX,
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(PhoenixState),
    .class_init = phoenix_class_init,
    .instance_init = phoenix_instance_init,
    .instance_finalize = phoenix_instance_finalize,
    .interfaces = (InterfaceInfo[]){{INTERFACE_PCIE_DEVICE}, {}},
};

static void phoenix_register_types(void) {
  type_register_static(&phoenix_info);
}

type_init(phoenix_register_types)
