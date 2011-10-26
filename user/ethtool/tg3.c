#include <stdio.h>
#include <string.h>
#include "ethtool-util.h"

#define TG3_MAGIC 0x669955aa

int
tg3_dump_eeprom(struct ethtool_drvinfo *info, struct ethtool_eeprom *ee)
{
	int i;

	if (ee->magic != TG3_MAGIC) {
		fprintf(stderr, "Magic number 0x%08x does not match 0x%08x\n",
			ee->magic, TG3_MAGIC);
		return -1;
	}

	fprintf(stdout, "Address   \tData\n");
	fprintf(stdout, "----------\t----\n");
	for (i = 0; i < ee->len; i++)
		fprintf(stdout, "0x%08x\t0x%02x\n", i + ee->offset, ee->data[i]);

	return 0;
}

int
tg3_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs)
{
	int i, j;
	int reg_boundaries[] = { 0x015c, 0x0200, 0x0400, 0x0400, 0x08f0, 0x0c00,
	       			 0x0ce0, 0x1000, 0x1004, 0x1400, 0x1480, 0x1800,
				 0x1848, 0x1c00, 0x1c04, 0x2000, 0x225c, 0x2400,
				 0x24c4, 0x2800, 0x2804, 0x2c00, 0x2c20, 0x3000,
				 0x3014, 0x3400, 0x3408, 0x3800, 0x3808, 0x3c00,
				 0x3d00, 0x4000, 0x4010, 0x4400, 0x4458, 0x4800,
				 0x4808, 0x4c00, 0x4c08, 0x5000, 0x5280, 0x5400,
				 0x5680, 0x5800, 0x5a10, 0x5c00, 0x5d20, 0x6000,
				 0x600c, 0x6800, 0x6848, 0x7000, 0x7034, 0x7c00,
				 0x7e40, 0x8000 };

	fprintf(stdout, "Offset\tValue\n");
	fprintf(stdout, "------\t----------\n");
	for (i = 0, j = 0; i < regs->len; ) {
		u32 reg;

		memcpy(&reg, &regs->data[i], 4);
		fprintf(stdout, "0x%04x\t0x%08x\n", i, reg);

		i += 4;
		if (i == reg_boundaries[j]) {
			i = reg_boundaries[j + 1];
			j += 2;
			fprintf(stdout, "\n");
		}
	}
	fprintf(stdout, "\n");
	return 0;
}
