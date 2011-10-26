/*
 * Wireless LAN card I/O debugging tool for Host AP kernel driver
 * Copyright (c) 2003, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>


#define PRISM2_IO_DEBUG_CMD_INB 0
#define PRISM2_IO_DEBUG_CMD_INW 1
#define PRISM2_IO_DEBUG_CMD_INSW 2
#define PRISM2_IO_DEBUG_CMD_OUTB 3
#define PRISM2_IO_DEBUG_CMD_OUTW 4
#define PRISM2_IO_DEBUG_CMD_OUTSW 5
#define PRISM2_IO_DEBUG_CMD_ERROR 6
#define PRISM2_IO_DEBUG_CMD_INTERRUPT 7


/* PC Card / PLX registers */
#define PCCARD_CMD_OFF 0x00
#define PCCARD_PARAM0_OFF 0x02
#define PCCARD_PARAM1_OFF 0x04
#define PCCARD_PARAM2_OFF 0x06
#define PCCARD_STATUS_OFF 0x08
#define PCCARD_RESP0_OFF 0x0A
#define PCCARD_RESP1_OFF 0x0C
#define PCCARD_RESP2_OFF 0x0E
#define PCCARD_INFOFID_OFF 0x10
#define PCCARD_CONTROL_OFF 0x14
#define PCCARD_SELECT0_OFF 0x18
#define PCCARD_SELECT1_OFF 0x1A
#define PCCARD_OFFSET0_OFF 0x1C
#define PCCARD_OFFSET1_OFF 0x1E
#define PCCARD_RXFID_OFF 0x20
#define PCCARD_ALLOCFID_OFF 0x22
#define PCCARD_TXCOMPLFID_OFF 0x24
#define PCCARD_SWSUPPORT0_OFF 0x28
#define PCCARD_SWSUPPORT1_OFF 0x2A
#define PCCARD_SWSUPPORT2_OFF 0x2C
#define PCCARD_EVSTAT_OFF 0x30
#define PCCARD_INTEN_OFF 0x32
#define PCCARD_EVACK_OFF 0x34
#define PCCARD_DATA0_OFF 0x36
#define PCCARD_DATA1_OFF 0x38
#define PCCARD_AUXPAGE_OFF 0x3A
#define PCCARD_AUXOFFSET_OFF 0x3C
#define PCCARD_AUXDATA_OFF 0x3E


/* PCI registers */
#define PCI_CMD_OFF 0x00
#define PCI_PARAM0_OFF 0x04
#define PCI_PARAM1_OFF 0x08
#define PCI_PARAM2_OFF 0x0C
#define PCI_STATUS_OFF 0x10
#define PCI_RESP0_OFF 0x14
#define PCI_RESP1_OFF 0x18
#define PCI_RESP2_OFF 0x1C
#define PCI_INFOFID_OFF 0x20
#define PCI_CONTROL_OFF 0x28
#define PCI_SELECT0_OFF 0x30
#define PCI_SELECT1_OFF 0x34
#define PCI_OFFSET0_OFF 0x38
#define PCI_OFFSET1_OFF 0x3C
#define PCI_RXFID_OFF 0x40
#define PCI_ALLOCFID_OFF 0x44
#define PCI_TXCOMPLFID_OFF 0x48
#define PCI_PCICOR_OFF 0x4C
#define PCI_SWSUPPORT0_OFF 0x50
#define PCI_SWSUPPORT1_OFF 0x54
#define PCI_SWSUPPORT2_OFF 0x58
#define PCI_PCIHCR_OFF 0x5C
#define PCI_EVSTAT_OFF 0x60
#define PCI_INTEN_OFF 0x64
#define PCI_EVACK_OFF 0x68
#define PCI_DATA0_OFF 0x6C
#define PCI_DATA1_OFF 0x70
#define PCI_AUXPAGE_OFF 0x74
#define PCI_AUXOFFSET_OFF 0x78
#define PCI_AUXDATA_OFF 0x7C
#define PCI_PCI_M0_ADDRH_OFF 0x80
#define PCI_PCI_M0_ADDRL_OFF 0x84
#define PCI_PCI_M0_LEN_OFF 0x88
#define PCI_PCI_M0_CTL_OFF 0x8C
#define PCI_PCI_STATUS_OFF 0x98
#define PCI_PCI_M1_ADDRH_OFF 0xA0
#define PCI_PCI_M1_ADDRL_OFF 0xA4
#define PCI_PCI_M1_LEN_OFF 0xA8
#define PCI_PCI_M1_CTL_OFF 0xAC


struct reg_info {
	int reg;
	char *name;
};


static struct reg_info prism2_pccard_regs[] =
{
	{ PCCARD_CMD_OFF, "CMD" },
	{ PCCARD_PARAM0_OFF, "PARAM0" },
	{ PCCARD_PARAM1_OFF, "PARAM1" },
	{ PCCARD_PARAM2_OFF, "PARAM2" },
	{ PCCARD_STATUS_OFF, "STATUS" },
	{ PCCARD_RESP0_OFF, "RESP0" },
	{ PCCARD_RESP1_OFF, "RESP1" },
	{ PCCARD_RESP2_OFF, "RESP2" },
	{ PCCARD_INFOFID_OFF, "INFOFID" },
	{ PCCARD_CONTROL_OFF, "CONTROL" },
	{ PCCARD_SELECT0_OFF, "SELECT0" },
	{ PCCARD_SELECT1_OFF, "SELECT1" },
	{ PCCARD_OFFSET0_OFF, "OFFSET0" },
	{ PCCARD_OFFSET1_OFF, "OFFSET1" },
	{ PCCARD_RXFID_OFF, "RXFID" },
	{ PCCARD_ALLOCFID_OFF, "ALLOCFID" },
	{ PCCARD_TXCOMPLFID_OFF, "TXCOMPLFID" },
	{ PCCARD_SWSUPPORT0_OFF, "SWSUPPORT0" },
	{ PCCARD_SWSUPPORT1_OFF, "SWSUPPORT1" },
	{ PCCARD_SWSUPPORT2_OFF, "SWSUPPORT2" },
	{ PCCARD_EVSTAT_OFF, "EVSTAT" },
	{ PCCARD_INTEN_OFF, "INTEN" },
	{ PCCARD_EVACK_OFF, "EVACK" },
	{ PCCARD_DATA0_OFF, "DATA0" },
	{ PCCARD_DATA1_OFF, "DATA1" },
	{ PCCARD_AUXPAGE_OFF, "AUXPAGE" },
	{ PCCARD_AUXOFFSET_OFF, "AUXOFFSET" },
	{ PCCARD_AUXDATA_OFF, "AUXDATA" },
	{ 0, NULL }
};

static struct reg_info prism2_pci_regs[] =
{
	{ PCI_CMD_OFF, "CMD" },
	{ PCI_PARAM0_OFF, "PARAM0" },
	{ PCI_PARAM1_OFF, "PARAM1" },
	{ PCI_PARAM2_OFF, "PARAM2" },
	{ PCI_STATUS_OFF, "STATUS" },
	{ PCI_RESP0_OFF, "RESP0" },
	{ PCI_RESP1_OFF, "RESP1" },
	{ PCI_RESP2_OFF, "RESP2" },
	{ PCI_INFOFID_OFF, "INFOFID" },
	{ PCI_CONTROL_OFF, "CONTROL" },
	{ PCI_SELECT0_OFF, "SELECT0" },
	{ PCI_SELECT1_OFF, "SELECT1" },
	{ PCI_OFFSET0_OFF, "OFFSET0" },
	{ PCI_OFFSET1_OFF, "OFFSET1" },
	{ PCI_RXFID_OFF, "RXFID" },
	{ PCI_ALLOCFID_OFF, "ALLOCFID" },
	{ PCI_TXCOMPLFID_OFF, "TXCOMPLFID" },
	{ PCI_SWSUPPORT0_OFF, "SWSUPPORT0" },
	{ PCI_SWSUPPORT1_OFF, "SWSUPPORT1" },
	{ PCI_SWSUPPORT2_OFF, "SWSUPPORT2" },
	{ PCI_EVSTAT_OFF, "EVSTAT" },
	{ PCI_INTEN_OFF, "INTEN" },
	{ PCI_EVACK_OFF, "EVACK" },
	{ PCI_DATA0_OFF, "DATA0" },
	{ PCI_DATA1_OFF, "DATA1" },
	{ PCI_AUXPAGE_OFF, "AUXPAGE" },
	{ PCI_AUXOFFSET_OFF, "AUXOFFSET" },
	{ PCI_AUXDATA_OFF, "AUXDATA" },
	{ 0, NULL }
};

static struct reg_info *prism2_regs = prism2_pccard_regs;


static const char * cmd_str(int cmd)
{
	switch (cmd) {
	case PRISM2_IO_DEBUG_CMD_INB: return "INB";
	case PRISM2_IO_DEBUG_CMD_INW: return "INW";
	case PRISM2_IO_DEBUG_CMD_INSW: return "INSW";
	case PRISM2_IO_DEBUG_CMD_OUTB: return "OUTB";
	case PRISM2_IO_DEBUG_CMD_OUTW: return "OUTW";
	case PRISM2_IO_DEBUG_CMD_OUTSW: return "OUTSW";
	case PRISM2_IO_DEBUG_CMD_ERROR: return "ERROR";
	case PRISM2_IO_DEBUG_CMD_INTERRUPT: return "INTERRUPT";
	default: return "??";
	};
}


static const char * addr_str(int cmd, int addr)
{
	static char buf[32];
	struct reg_info *reg = prism2_regs;

	if (cmd == PRISM2_IO_DEBUG_CMD_ERROR)
		return "";

	while (reg->name) {
		if (reg->reg == addr)
			return reg->name;
		reg++;
	}

	snprintf(buf, sizeof(buf), "%d", addr);
	return buf;
}


int main(int argc, char *argv[])
{
	FILE *f;
	uint32_t buf[65536];
	size_t len;
	int i;

	if (argc < 2) {
		fprintf(stderr, "hostap_io_debug [-p] <file name>\n\n"
			"example: "
			"hostap_io_debug /proc/net/hostap/wlan0/io_debug\n");
		exit(1);
	}

	i = 1;
	if (strcmp(argv[i], "-p") == 0) {
		i++;
		printf("PCI\n");
		prism2_regs = prism2_pci_regs;
	}
	f = fopen(argv[i], "r");
	if (f == NULL) {
		fprintf(stderr, "File '%s' not found.\n", argv[1]);
		exit(1);
	}

	len = fread(buf, 1, sizeof(buf), f);
	for (i = 0; i < len / 4; i += 2) {
		uint32_t cmd, addr, val;
		cmd = buf[i + 1] >> 24;
		addr = (buf[i + 1] >> 16) & 0xff;
		val = buf[i + 1] & 0xffff;
		printf("%09d %s %s 0x%04x\n", buf[i], cmd_str(cmd),
		       addr_str(cmd, addr), val);
	}
	fclose(f);

	return 0;
}
