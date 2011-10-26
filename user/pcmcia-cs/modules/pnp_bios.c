/*
 * PnP bios services
 * 
 * Originally (C) 1998 Christian Schmidt (chr.schmidt@tu-bs.de)
 * Modifications (c) 1998 Tom Lees <tom@lpsg.demon.co.uk>
 * Minor reorganizations by David Hinds <dahinds@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *   Reference:
 *   Compaq Computer Corporation, Phoenix Technologies Ltd., Intel 
 *   Corporation. 
 *   Plug and Play BIOS Specification, Version 1.0A, May 5, 1994
 *   Plug and Play BIOS Clarification Paper, October 6, 1994
 *
 */

#include <pcmcia/config.h>
#define __NO_VERSION__
#include <pcmcia/k_compat.h>

#include <linux/types.h>
#include <linux/module.h>
#include <linux/linkage.h>
#include <linux/kernel.h>
#include <linux/pnp_bios.h>
#include <asm/page.h>
#include <asm/system.h>
#include <asm/desc.h>

/* PnP bios signature: "$PnP" */
#define PNP_SIGNATURE   (('$' << 0) + ('P' << 8) + ('n' << 16) + ('P' << 24))

#ifdef MODULE
static struct desc_struct *gdt;
#endif

/*
 * This is the standard structure used to identify the entry point
 * to the Plug and Play bios
 */
#pragma pack(1)
union pnpbios {
	struct {
		u32 signature;    /* "$PnP" */
		u8 version;	  /* in BCD */
		u8 length;	  /* length in bytes, currently 21h */
		u16 control;	  /* system capabilities */
		u8 checksum;	  /* all bytes must add up to 0 */

		u32 eventflag;    /* phys. address of the event flag */
		u16 rmoffset;     /* real mode entry point */
		u16 rmcseg;
		u16 pm16offset;   /* 16 bit protected mode entry */
		u32 pm16cseg;
		u32 deviceID;	  /* EISA encoded system ID or 0 */
		u16 rmdseg;	  /* real mode data segment */
		u32 pm16dseg;	  /* 16 bit pm data segment base */
	} fields;
	char chars[0x21];	  /* To calculate the checksum */
};
#pragma pack()

/*
 * Local Variables
 */
static struct {
	u32	offset;
	u16	segment;
} pnp_bios_callpoint;

static union pnpbios * pnp_bios_inst_struc = NULL;

/* The PnP entries in the GDT */
#define PNP_GDT		0x0038
#define PNP_CS32	(PNP_GDT+0x00)	/* segment for calling fn */
#define PNP_CS16	(PNP_GDT+0x08)	/* code segment for bios */
#define PNP_DS		(PNP_GDT+0x10)	/* data segment for bios */
#define PNP_TS1		(PNP_GDT+0x18)	/* transfer data segment */
#define PNP_TS2		(PNP_GDT+0x20)	/* another data segment */

static struct desc_struct saved_gdt[5];
static struct desc_struct pnp_gdt[] = {
	{ 0, 0x00c09a00 },	/* 32-bit code */
	{ 0, 0x00809a00 },	/* 16-bit code */
	{ 0, 0x00809200 },	/* 16-bit data */
	{ 0, 0x00809200 },	/* 16-bit data */
	{ 0, 0x00809200 }	/* 16-bit data */
};

/*
 * GDT abuse: since we want this to work when loaded as a module on a
 * normal kernel, we drop the PnP GDT entries on top of the APM stuff
 * and protect it with a spin lock (
 */

static long gdt_flags;
#ifdef USE_SPIN_LOCKS
static spinlock_t gdt_lock = SPIN_LOCK_UNLOCKED;
#endif

static void push_pnp_gdt(void)
{
	spin_lock_irqsave(&gdt_lock, gdt_flags);
	memcpy(saved_gdt, &gdt[PNP_GDT >> 3], sizeof(saved_gdt));
	memcpy(&gdt[PNP_GDT >> 3], pnp_gdt, sizeof(pnp_gdt));
}

static void pop_pnp_gdt(void)
{
	memcpy(pnp_gdt, &gdt[PNP_GDT >> 3], sizeof(pnp_gdt));
	memcpy(&gdt[PNP_GDT >> 3], saved_gdt, sizeof(saved_gdt));
	spin_unlock_irqrestore(&gdt_lock, gdt_flags);
}

/* 
 * These are some opcodes for a "static asmlinkage"
 * As this code is *not* executed inside the linux kernel segment, but in a
 * alias at offset 0, we need a far return that can not be compiled by
 * default (please, prove me wrong! this is *really* ugly!) 
 * This is the only way to get the bios to return into the kernel code,
 * because the bios code runs in 16 bit protected mode and therefore can only
 * return to the caller if the call is within the first 64kB, and the linux
 * kernel begins at offset 1MB...
 */
static u8 pnp_bios_callfunc[] =
{
	0x52,			              /* push edx */
	0x51,			              /* push ecx */
	0x53,			              /* push ebx */
	0x50,			              /* push eax */
	0x66, 0x9a, 0, 0,	              /* call far pnp_cs16:0, offset */
	(PNP_CS16) & 0xff, (PNP_CS16) >> 8,   /* becomes fixed up later */
	0x83, 0xc4, 0x10,	              /* add esp, 16 */
	0xcb};			              /* retf */

#define Q_SET_SEL(selname, address, size) \
set_base (gdt [(selname) >> 3], __va((u32)(address))); \
set_limit (gdt [(selname) >> 3], size)

#define Q2_SET_SEL(selname, address, size) \
set_base (gdt [(selname) >> 3], (u32)(address)); \
set_limit (gdt [(selname) >> 3], size)

/*
 * Callable Functions
 */
#define PNP_GET_NUM_SYS_DEV_NODES       0x00
#define PNP_GET_SYS_DEV_NODE            0x01
#define PNP_SET_SYS_DEV_NODE            0x02
#define PNP_GET_EVENT                   0x03
#define PNP_SEND_MESSAGE                0x04
#define PNP_GET_DOCKING_STATION_INFORMATION 0x05
#define PNP_SET_STATIC_ALLOCED_RES_INFO 0x09
#define PNP_GET_STATIC_ALLOCED_RES_INFO 0x0a
#define PNP_GET_APM_ID_TABLE            0x0b
#define PNP_GET_PNP_ISA_CONFIG_STRUC    0x40
#define PNP_GET_ESCD_INFO               0x41
#define PNP_READ_ESCD                   0x42
#define PNP_WRITE_ESCD                  0x43

/*
 * Call pnp bios with function 0x00, "get number of system device nodes"
 */
int pnp_bios_dev_node_info(struct pnp_dev_node_info *data)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, data, sizeof(struct pnp_dev_node_info));
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_GET_NUM_SYS_DEV_NODES),
            "b"((2 << 16) | PNP_TS1),
            "c"((PNP_DS << 16) | PNP_TS1)
           :"memory");
	data->no_nodes &= 0xff;
	pop_pnp_gdt();
	return status;
}

/* 
 * Call pnp bios with function 0x01, "get system device node"
 * Input:  *nodenum=desired node, 
 *         static=1: config (dynamic) config, else boot (static) config,
 * Output: *nodenum=next node or 0xff if no more nodes
 */
int pnp_bios_get_dev_node(u8 *nodenum, char config, struct pnp_bios_node *data)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, nodenum, sizeof(char));
	Q2_SET_SEL(PNP_TS2, data, 64 * 1024);
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_GET_SYS_DEV_NODE),
            "b"(PNP_TS1),
            "c"(((config ? 1 : 2) <<16) | PNP_TS2),
            "d"(PNP_DS)
           :"memory");
	pop_pnp_gdt();
	return status;
}

/*
 * Call pnp bios with function 0x02, "set system device node"
 * Input: nodenum=desired node, 
 *        static=1: config (dynamic) config, else boot (static) config,
 */
int pnp_bios_set_dev_node(u8 nodenum, char config, struct pnp_bios_node *data)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, data, /* *((u16 *) data)*/ 65536);
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(((u32) nodenum << 16) | PNP_SET_SYS_DEV_NODE),
            "b"(PNP_TS1 << 16),
            "c"((PNP_DS << 16) | (config ? 1 : 2))
           :"memory");
	pop_pnp_gdt();
	return status;
}

/*
 * Call pnp bios with function 0x03, "get event"
 */
#if needed
int pnp_bios_get_event(u16 *event)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, event, sizeof(u16));
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_GET_EVENT),
            "b"((PNP_DS << 16) | PNP_TS1)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/* 
 * Call pnp bios with function 0x04, "send message"
 */
#if needed
int pnp_bios_send_message(u16 message)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(((u32) message << 16) | PNP_SEND_MESSAGE),
            "b"(PNP_DS)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/*
 * Call pnp bios with function 0x05, "get docking station information"
 */
#if needed
int pnp_bios_dock_station_info(struct pnp_docking_station_info *data)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, data, sizeof(struct pnp_docking_station_info));
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_GET_DOCKING_STATION_INFORMATION),
            "b"((PNP_TS1 << 16) | PNP_DS)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/*
 * Call pnp bios with function 0x09, "set statically allocated resource
 * information"
 */
#if needed
int pnp_bios_set_stat_res(char *info)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, info, *((u16 *) info));
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_SET_STATIC_ALLOCED_RES_INFO),
            "b"((PNP_TS1 << 16) | PNP_DS)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/*
 * Call pnp bios with function 0x0a, "get statically allocated resource
 * information"
 */
#if needed
int pnp_bios_get_stat_res(char *info)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, info, 64 * 1024);
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_GET_STATIC_ALLOCED_RES_INFO),
            "b"((PNP_TS1 << 16) | PNP_DS)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/*
 * Call pnp bios with function 0x0b, "get APM id table"
 */
#if needed
int pnp_bios_apm_id_table(char *table, u16 *size)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, table, *size);
	Q2_SET_SEL(PNP_TS2, size, sizeof(u16));
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_GET_APM_ID_TABLE),
            "b"(PNP_TS2),
            "c"((PNP_DS << 16) | PNP_TS1)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/*
 * Call pnp bios with function 0x40, "get isa pnp configuration structure"
 */
#if needed
int pnp_bios_isapnp_config(struct pnp_isa_config_struc *data)
{
	u16 status;
	if (!pnp_bios_present ())
		return PNP_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, data, sizeof(struct pnp_isa_config_struc));
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_GET_PNP_ISA_CONFIG_STRUC),
            "b"((PNP_DS << 16) | PNP_TS1)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/*
 * Call pnp bios with function 0x41, "get ESCD info"
 */
#if needed
int pnp_bios_escd_info(struct escd_info_struc *data)
{
	u16 status;
	if (!pnp_bios_present ())
		return ESCD_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, data, sizeof(struct escd_info_struc));
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_GET_ESCD_INFO),
            "b"((2 << 16) | PNP_TS1),
            "c"((4 << 16) | PNP_TS1),
            "d"((PNP_DS << 16) | PNP_TS1)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/*
 * Call pnp bios function 0x42, "read ESCD"
 * nvram_base is determined by calling escd_info
 */
#if needed
int pnp_bios_read_escd(char *data, u32 nvram_base)
{
	u16 status;
	if (!pnp_bios_present ())
		return ESCD_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, data, 64 * 1024);
	set_base(gdt[PNP_TS2 >> 3], nvram_base);
	set_limit(gdt[PNP_TS2 >> 3], 64 * 1024);
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_READ_ESCD),
            "b"((PNP_TS2 << 16) | PNP_TS1),
            "c"(PNP_DS)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

/*
 * Call pnp bios function 0x43, "write ESCD"
 */
#if needed
int pnp_bios_write_escd(char *data, u32 nvram_base)
{
	u16 status;
	if (!pnp_bios_present ())
		return ESCD_FUNCTION_NOT_SUPPORTED;
	push_pnp_gdt();
	Q2_SET_SEL(PNP_TS1, data, 64 * 1024);
	set_base(gdt[PNP_TS2 >> 3], nvram_base);
	set_limit(gdt[PNP_TS2 >> 3], 64 * 1024);
	__asm__ __volatile__
          ("lcall %%cs:" SYMBOL_NAME_STR(pnp_bios_callpoint) "\n\t"
           :"=a"(status)
           :"a"(PNP_WRITE_ESCD),
            "b"((PNP_TS2 << 16) | PNP_TS1),
            "c"(PNP_DS)
           :"memory");
	pop_pnp_gdt();
	return status;
}
#endif

int pnp_bios_present(void)
{
  return (pnp_bios_inst_struc != NULL);
}

/* 
 * Searches the defined area (0xf0000-0xffff0) for a valid PnP BIOS
 * structure and, if found one, sets up the selectors and entry points
 */

void pnp_bios_init(void)
{
	union pnpbios *check;
	u8 sum;
	int i, length;

#ifdef MODULE
	struct Xgt_desc_struct my_gdt_descr;
	__asm__ __volatile__ ("sgdt %0" : : "m" (my_gdt_descr));
	gdt = (struct desc_struct *)my_gdt_descr.address;
#endif

	for (check = (union pnpbios *) __va(0xf0000);
	     check < (union pnpbios *) __va(0xffff0);
	     ((void *) (check)) += 16) {
		if (check->fields.signature != PNP_SIGNATURE)
			continue;
		length = check->fields.length;
		if (!length)
			continue;
		for (sum = 0, i = 0; i < length; i++)
			sum += check->chars[i];
		if (sum)
			continue;
		if (check->fields.version < 0x10) {
			printk(KERN_WARNING "PnP: unsupported version %d.%d",
			       check->fields.version >> 4,
			       check->fields.version & 15);
			continue;
		}
		printk(KERN_INFO "PnP: PNP BIOS installation structure at 0x%p\n",
		       check);
		printk(KERN_INFO "PnP: PNP BIOS version %d.%d, entry at %x:%x, dseg at %x\n",
                       check->fields.version >> 4, check->fields.version & 15,
		       check->fields.pm16cseg, check->fields.pm16offset,
		       check->fields.pm16dseg);
		push_pnp_gdt();
		Q2_SET_SEL(PNP_CS32, &pnp_bios_callfunc,
			   sizeof(pnp_bios_callfunc));
		Q_SET_SEL(PNP_CS16, check->fields.pm16cseg, 64 * 1024);
		Q_SET_SEL(PNP_DS, check->fields.pm16dseg, 64 * 1024);
		pop_pnp_gdt();
		pnp_bios_callfunc[6] = check->fields.pm16offset & 0xff;
		pnp_bios_callfunc[7] = check->fields.pm16offset >> 8;
		pnp_bios_callpoint.offset = 0;
		pnp_bios_callpoint.segment = PNP_CS32;
		pnp_bios_inst_struc = check;
		break;
	}
}
