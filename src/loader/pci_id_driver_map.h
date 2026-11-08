#ifndef _PCI_ID_DRIVER_MAP_H_
#define _PCI_ID_DRIVER_MAP_H_

#include <stdbool.h>
#include <stddef.h>

#ifndef __IS_LOADER
#  error "Only include from loader.c"
#endif

static const int i830_chip_ids[] = {
#define CHIPSET(chip, desc, name) chip,
#include "pci_ids/i830_pci_ids.h"
#undef CHIPSET
};

static const int i915_chip_ids[] = {
#define CHIPSET(chip, desc, name) chip,
#include "pci_ids/i915_pci_ids.h"
#undef CHIPSET
};

static const int r100_chip_ids[] = {
#define CHIPSET(chip, name, family) chip,
#include "pci_ids/radeon_pci_ids.h"
#undef CHIPSET
};

static const int r200_chip_ids[] = {
#define CHIPSET(chip, name, family) chip,
#include "pci_ids/r200_pci_ids.h"
#undef CHIPSET
};

bool is_nouveau_vieux(int fd);

static const struct {
   int vendor_id;
   const char *driver;
   const int *chip_ids;
   int num_chips_ids;
   bool (*predicate)(int fd);
} driver_map[] = {
   { 0x8086, "i830", i830_chip_ids, ARRAY_SIZE(i830_chip_ids) },
   { 0x8086, "i915", i915_chip_ids, ARRAY_SIZE(i915_chip_ids) },
   { 0x1002, "radeon", r100_chip_ids, ARRAY_SIZE(r100_chip_ids) },
   { 0x1002, "r200", r200_chip_ids, ARRAY_SIZE(r200_chip_ids) },
   { 0x10de, "nouveau_vieux", NULL, -1, is_nouveau_vieux },
};

#endif /* _PCI_ID_DRIVER_MAP_H_ */
