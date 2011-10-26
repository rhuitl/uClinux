/*======================================================================

    A utility for dumping resource information for PnP devices

    lspnp.c 1.6 2000/06/12 21:54:45

    The contents of this file are subject to the Mozilla Public
    License Version 1.1 (the "License"); you may not use this file
    except in compliance with the License. You may obtain a copy of
    the License at http://www.mozilla.org/MPL/

    Software distributed under the License is distributed on an "AS
    IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
    implied. See the License for the specific language governing
    rights and limitations under the License.

    The initial developer of the original code is David A. Hinds
    <dahinds@users.sourceforge.net>.  Portions created by David A. Hinds
    are Copyright (C) 1999 David A. Hinds.  All Rights Reserved.

    Alternatively, the contents of this file may be used under the
    terms of the GNU Public License version 2 (the "GPL"), in which
    case the provisions of the GPL are applicable instead of the
    above.  If you wish to allow the use of your version of this file
    only under the terms of the GPL and not to allow others to use
    your version of this file under the MPL, indicate your decision
    by deleting the provisions above and replace them with the notice
    and other provisions required by the GPL.  If you do not delete
    the provisions above, a recipient may use your version of this
    file under either the MPL or the GPL.

    Usage:

    lspnp [-b] [-v[v]] [device #]

======================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <endian.h>
#include <ctype.h>
#include <asm/types.h>

#include <linux/pnp_resource.h>

static int verbose = 0, boot = 0;

static struct {
    __u8	base;
    char *	name;
} base_type[] = {
    { 1, "mass storage device" },
    { 2, "network interface controller" },
    { 3, "display controller" },
    { 4, "multimedia controller" },
    { 5, "memory controller" },
    { 6, "bridge controller" },
    { 7, "communications device" },
    { 8, "system peripheral" },
    { 9, "input device" },
    { 10, "service processor" }
};
#define NBASE	(sizeof(base_type)/sizeof(base_type[0]))

static struct {
    __u8	base, sub;
    char *	name;
} sub_type[] = {
    { 1, 0, "SCSI" },
    { 1, 1, "IDE" },
    { 1, 2, "floppy" },
    { 1, 3, "IPI" },
    { 2, 0, "ethernet" },
    { 2, 1, "token ring" },
    { 2, 2, "FDDI" },
    { 3, 0, "VGA" },
    { 3, 1, "SVGA" },
    { 3, 2, "XGA" },
    { 4, 0, "video" },
    { 4, 1, "audio" },
    { 5, 0, "RAM" },
    { 5, 1, "flash" },
    { 6, 0, "host processor" },
    { 6, 1, "ISA" },
    { 6, 2, "EISA" },
    { 6, 3, "MicroChannel" },
    { 6, 4, "PCI" },
    { 6, 5, "PCMCIA" },
    { 6, 6, "VME" },
    { 7, 0, "RS-232" },
    { 7, 1, "AT parallel port" },
    { 8, 0, "programmable interrupt controller" },
    { 8, 1, "DMA controller" },
    { 8, 2, "system timer" },
    { 8, 3, "real time clock" },
    { 8, 4, "L2 cache" },
    { 8, 5, "NVRAM" },
    { 8, 6, "power management" },
    { 8, 7, "CMOS" },
    { 8, 8, "operator panel" },
    { 9, 0, "keyboard" },
    { 9, 1, "digitizer" },
    { 9, 2, "mouse" },
    { 9, 3, "tablet" },
    { 10, 0, "general memory" }
};
#define NSUB	(sizeof(sub_type)/sizeof(sub_type[0]))

static struct eisa_id {
    char	id[8];
    char *	name;
    struct eisa_id * next;
} *eisa_id = NULL;

#define swap16(n) ((((n)&0x00ff)<<8) | (((n)&0xff00)>>8))
#define swap32(n) \
    ((((n)&0xff000000)>>24) | (((n)&0x00ff0000)>>8) | \
     (((n)&0x0000ff00)<<8)  | (((n)&0x000000ff)<<24))

#if (__BYTE_ORDER == _BIG_ENDIAN)
#define flip16(n)	swap16(n)
#define flip32(n)	swap32(n)
#else
#define flip16(n)	(n)
#define flip32(n)	(n)
#endif

/*====================================================================*/

#define HEX(id,a) hex[((id)>>a) & 15]
#define CHAR(id,a) (0x40 + (((id)>>a) & 31))

static char *eisa_str(__u32 id)
{
    const char *hex = "0123456789abcdef";
    static char str[8];
    id = swap32(id);
    str[0] = CHAR(id, 26);
    str[1] = CHAR(id, 21);
    str[2] = CHAR(id,16);
    str[3] = HEX(id, 12);
    str[4] = HEX(id, 8);
    str[5] = HEX(id, 4);
    str[6] = HEX(id, 0);
    str[7] = '\0';
    return str;
}

static void load_ids(void)
{
    char s[133], *t;
    int n;
    struct eisa_id *id;
    FILE *f = fopen("/usr/share/pnp.ids", "r");
    
    if (f == NULL)
	return;
    while (fgets(s, sizeof(s), f)) {
	if ((strlen(s) < 9) ||
	    !(isupper(s[0]) && isupper(s[1]) && isupper(s[2]) &&
	      isxdigit(s[3]) && isxdigit(s[4]) && isxdigit(s[5]) &&
	      isxdigit(s[6]))) continue;
	id = malloc(sizeof(struct eisa_id));
	strncpy(id->id, s, 7);
	for (n = 3; n < 7; n++)
	    id->id[n] = tolower(id->id[n]);
	id->id[7] = '\0';
	s[strlen(s)-1] = '\0';
	for (t = s+7; isspace(*t); t++) ;
	id->name = strdup(t);
	id->next = eisa_id; eisa_id = id;
    }
    fclose(f);
}

static void dump_flags(int flags)
{
    printf("    flags:");
    if (!flags)
	printf(" none");
    if (flags & 0x0001)
	printf(" [no disable]");
    if (flags & 0x0002)
	printf(" [no config]");
    if (flags & 0x0004)
	printf(" [output]");
    if (flags & 0x0008)
	printf(" [input]");
    if (flags & 0x0010)
	printf(" [bootable]");
    if (flags & 0x0020)
	printf(" [dock]");
    if (flags & 0x0040)
	printf(" [removable]");
    if ((flags & 0x0180) == 0x0000)
	printf(" [static]");
    if ((flags & 0x0180) == 0x0080)
	printf(" [dynamic]");
    if ((flags & 0x0180) == 0x0180)
	printf(" [dynamic only]");
    printf("\n");
}

static void dump_class(int t1, int t2)
{
    int i;
    for (i = 0; i < NBASE; i++)
	if (t1 == base_type[i].base) break;
    printf("%s: ", (i < NBASE) ? base_type[i].name : "reserved");
    for (i = 0; i < NSUB; i++)
	if ((t1 == sub_type[i].base) && (t2 == sub_type[i].sub))
	    break;
    printf("%s", (i < NSUB) ? sub_type[i].name : "other");
}

/*
  Small resource tags
*/

static void dump_version(union pnp_small_resource *r)
{
    printf("\tPnP version %d.%d, vendor version %d.%d\n",
	   r->version.pnp>>4, r->version.pnp & 0x0f,
	   r->version.vendor>>4, r->version.vendor & 0x0f);
}

static void dump_ldid(union pnp_small_resource *r, int sz)
{
    printf("\tlogical ID %s", eisa_str(r->ldid.id));
    if (verbose > 1) {
	if (r->ldid.flag0 & PNP_RES_LDID_BOOT)
	    printf(" [boot]");
    }
    printf("\n");
}

static void dump_gdid(union pnp_small_resource *r)
{
    struct eisa_id *eid;
    char *eis = eisa_str(r->gdid.id);
    
    printf("\t%s", eis);
    for (eid = eisa_id; eid; eid = eid->next)
	if (strcmp(eis, eid->id) == 0) break;
    if (eid)
	printf(" %s\n", eid->name);
    else
	printf("\n");
}

static void dump_irq(union pnp_small_resource *r, int sz)
{
    int mask = flip16(r->irq.mask);
    printf("\tirq ");
    if (!mask) {
        printf("disabled");
    } else if (mask & (mask-1)) {
	printf("mask 0x%04x", mask);
    } else {
	printf("%d", ffs(mask)-1);
    }
    if (verbose > 1) {
	if (sz == 3) {
	    if (r->irq.info & PNP_RES_IRQ_HIGH_EDGE)
		printf(" [high edge]");
	    if (r->irq.info & PNP_RES_IRQ_LOW_EDGE)
		printf(" [low edge]");
	    if (r->irq.info & PNP_RES_IRQ_HIGH_LEVEL)
		printf(" [high level]");
	    if (r->irq.info & PNP_RES_IRQ_LOW_LEVEL)
		printf(" [low level]");
	} else {
	    printf(" [high edge]");
	}
    }
    printf("\n");
}

static void dump_dma(union pnp_small_resource *r)
{
    int mask = r->dma.mask;
    printf("\tdma ");
    if (!mask) {
        printf("disabled");
    } else if (mask & (mask-1)) {
	printf("mask 0x%04x", mask);
    } else {
	printf("%d", ffs(mask)-1);
    }
    if (verbose > 1) {
	switch (r->dma.info & PNP_RES_DMA_WIDTH_MASK) {
	case PNP_RES_DMA_WIDTH_8:
	    printf(" [8 bit]"); break;
	case PNP_RES_DMA_WIDTH_8_16:
	    printf(" [8/16 bit]"); break;
	case PNP_RES_DMA_WIDTH_16:
	    printf(" [16 bit]"); break;
	}
	if (r->dma.info & PNP_RES_DMA_BUSMASTER)
	    printf(" [master]");
	if (r->dma.info & PNP_RES_DMA_COUNT_BYTE)
	    printf(" [count byte]");
	if (r->dma.info & PNP_RES_DMA_COUNT_WORD)
	    printf(" [count word]");
	switch (r->dma.info & PNP_RES_DMA_SPEED_MASK) {
	case PNP_RES_DMA_SPEED_COMPAT: printf(" [compat]"); break;
	case PNP_RES_DMA_SPEED_TYPEA: printf(" [type A]"); break;
	case PNP_RES_DMA_SPEED_TYPEB: printf(" [type B]"); break;
	case PNP_RES_DMA_SPEED_TYPEF: printf(" [type F]"); break;
	}
    }
    printf("\n");
}

static void dump_dep_start(union pnp_small_resource *r, int sz)
{
    printf("\t[start dep fn");
    if (sz) {
	printf(": priority: ");
	switch (r->dep_start.priority) {
	case PNP_RES_CONFIG_GOOD:
	    printf("good"); break;
	case PNP_RES_CONFIG_ACCEPTABLE:
	    printf("acceptable"); break;
	case PNP_RES_CONFIG_SUBOPTIMAL:
	    printf("suboptimal"); break;
	default:
	    printf("reserved"); break;
	}
    }
    printf("]\n");
}

static void dump_dep_end(union pnp_small_resource *r)
{
    printf("\t[end dep fn]\n");
}

static void dump_io(union pnp_small_resource *r)
{
    int min = flip16(r->io.min), max = flip16(r->io.max);
    printf("\tio ");
    if (r->io.len == 0)
	printf("disabled");
    else if (min == max)
	printf("0x%04x-0x%04x", min, min+r->io.len-1);
    else
	printf("base 0x%04x-0x%04x align 0x%02x len 0x%02x",
	       min, max, r->io.align, r->io.len);
    if (verbose > 1) {
	if (r->io.info & PNP_RES_IO_DECODE_16)
	    printf(" [16-bit decode]");
    }
    printf("\n");
}

static void dump_io_fixed(union pnp_small_resource *r)
{
    int base = flip16(r->io_fixed.base);
    printf("\tio ");
    if (r->io_fixed.len == 0)
	printf("disabled\n");
    else
	printf("0x%04x-0x%04x\n", base, base+r->io_fixed.len-1);
}

/*
  Large resource tags
*/

static void dump_mem_info(__u8 info)
{
    switch (info & PNP_RES_MEM_WIDTH_MASK) {
    case PNP_RES_MEM_WIDTH_8:
	printf(" [8 bit]"); break;
    case PNP_RES_MEM_WIDTH_16:
	printf(" [16 bit]"); break;
    case PNP_RES_MEM_WIDTH_8_16:
	printf(" [8/16 bit]"); break;
    case PNP_RES_MEM_WIDTH_32:
	printf(" [32 bit]"); break;
    }
    printf((info & PNP_RES_MEM_WRITEABLE) ? " [r/w]" : " [r/o]");
    if (info & PNP_RES_MEM_CACHEABLE)
	printf(" [cacheable]");
    if (info & PNP_RES_MEM_HIGH_ADDRESS)
	printf(" [high]");
    if (info & PNP_RES_MEM_SHADOWABLE)
	printf(" [shadow]");
    if (info & PNP_RES_MEM_EXPANSION_ROM)
	printf(" [rom]");
}

static void dump_ansi(union pnp_large_resource *r, int sz)
{
    printf("\tidentifier '%*s'\n", sz, r->ansi.str);
}

static void dump_mem(union pnp_large_resource *r)
{
    int min = flip16(r->mem.min) << 8;
    int max = flip16(r->mem.max) << 8;
    int align = flip16(r->mem.align), len = flip16(r->mem.len);
    printf("\tmem ");
    if (len == 0)
	printf("disabled");
    else if (min == max)
	printf("0x%06x-0x%06x", min, min+len-1);
    else
	printf("base 0x%06x-%06x, align 0x%04x, len 0x%06x",
	       min, max, align ? align : 0x10000, len<<8);
    if (verbose > 1)
	dump_mem_info(r->mem.info);
    printf("\n");
}

static void dump_mem32(union pnp_large_resource *r)
{
    u_int min = flip32(r->mem32.min), max = flip32(r->mem32.max);
    u_int align = flip32(r->mem32.align), len = flip32(r->mem32.len);
    printf("\tmem ");
    if (len == 0)
	printf("disabled");
    else if (min == max)
	printf("0x%08x-0x%08x", min, min+len-1);
    else
	printf("\tmem base 0x%08x-0x%08x align 0x%06x len 0x%06x",
	   min, max, align, len);
    if (verbose > 1)
	dump_mem_info(r->mem32.info);
    printf("\n");
}

static void dump_mem32_fixed(union pnp_large_resource *r)
{
    u_int base = flip32(r->mem32_fixed.base);
    u_int len = flip32(r->mem32_fixed.len);
    printf("\tmem ");
    if (len == 0)
	printf("disabled");
    else
	printf("0x%08x-0x%08x", base, base+len-1);
    if (verbose > 1)
	dump_mem_info(r->mem32_fixed.info);
    printf("\n");
}

/*====================================================================*/

static char *dump_chain(u_char *buf, int nr)
{
    union pnp_resource *p = (union pnp_resource *)buf;
    int tag = 0, sz;
    
    while (((u_char *)p < buf+nr) && (tag != PNP_RES_SMTAG_END)) {
	if (p->lg.tag & PNP_RES_LARGE_ITEM) {
	    union pnp_large_resource *r = &p->lg.d;
	    tag = p->lg.tag & ~PNP_RES_LARGE_ITEM;
	    sz = flip16(p->lg.sz) + 2;
	    switch (tag) {
	    case PNP_RES_LGTAG_MEM:
		dump_mem(r); break;
	    case PNP_RES_LGTAG_ID_ANSI:
		dump_ansi(r, sz); break;
	    case PNP_RES_LGTAG_ID_UNICODE:
		/* dump_unicode(r); */ break;
	    case PNP_RES_LGTAG_MEM32:
		dump_mem32(r); break;
	    case PNP_RES_LGTAG_MEM32_FIXED:
		dump_mem32_fixed(r); break;
	    }
	} else {
	    union pnp_small_resource *r = &p->sm.d;
	    tag = (p->sm.tag >> 3); sz = (p->sm.tag & 7);
	    switch (tag) {
	    case PNP_RES_SMTAG_VERSION:
		dump_version(r); break;
	    case PNP_RES_SMTAG_LDID:
		dump_ldid(r, sz); break;
	    case PNP_RES_SMTAG_CDID:
		dump_gdid(r); break;
	    case PNP_RES_SMTAG_IRQ:
		dump_irq(r, sz); break;
	    case PNP_RES_SMTAG_DMA:
		dump_dma(r); break;
	    case PNP_RES_SMTAG_DEP_START:
		dump_dep_start(r, sz); break;
	    case PNP_RES_SMTAG_DEP_END:
		dump_dep_end(r); break;
	    case PNP_RES_SMTAG_IO:
		dump_io(r); break;
	    case PNP_RES_SMTAG_IO_FIXED:
		dump_io_fixed(r); break;
	    }
	}
	(u_char *)p += sz + 1;
    }
    return (u_char *)p;
}

static void dump_resources(int num)
{
    char fn[40];
    u_char buf[4096], *p;
    int fd, nr;
    
    sprintf(fn, "/proc/bus/pnp/%s%02x", (boot ? "boot/" : ""), num);
    fd = open(fn, O_RDONLY);
    nr = read(fd, buf, sizeof(buf));
    close(fd);
    if (nr > 0) {
	if (verbose > 1)
	    printf("    allocated resources:\n");
	p = dump_chain(buf, nr);
	if (verbose > 1) {
	    if (p+4 < buf+nr) {
		printf("    possible resources:\n");
	    }
	    p = dump_chain(p, nr);
	    if (p+2 < buf+nr) {
		printf("    compatible devices:\n");
		p = dump_chain(p, nr);
	    }
	}
    }
}

static int dump_basic(int match)
{
    int id, num, t1, t2, t3, flags;
    struct eisa_id *eid;
    char *eis, buf[64];
    FILE *f;

    f = fopen("/proc/bus/pnp/devices", "r");
    if (f == NULL) {
	fprintf(stderr, "lspnp: /proc/bus/pnp not available\n");
	return -1;
    }
    while (fgets(buf, 63, f) != NULL) {
	sscanf(buf, "%x %x %x:%x:%x %x", &num, &id, &t1, &t2, &t3, &flags);
	if ((match >= 0) && (match != num))
	    continue;
	eis = eisa_str(id);
	printf("%02x %7s ", num, eis);
	for (eid = eisa_id; eid; eid = eid->next)
	    if (strcmp(eis, eid->id) == 0) break;
	if (eid)
	    printf("%s", eid->name);
	else
	    dump_class(t1, t2);
	printf("\n");
	if (verbose > 1)
	    dump_flags(flags);
	if (verbose) {
	    dump_resources(num);
	    if (match < 0) printf("\n");
	}
    }
    fclose(f);
    return 0;
}

/*====================================================================*/

void usage(char *name)
{
    fprintf(stderr, "usage: %s [-b] [-v[v]] [device #]\n", name);
    exit(EXIT_FAILURE);
}
    
int main(int argc, char *argv[])
{
    int optch, errflg = 0;
    char *s;
    
    while ((optch = getopt(argc, argv, "bv")) != -1) {
	switch (optch) {
	case 'b':
	    boot++; break;
	case 'v':
	    verbose++; break;
	default:
	    errflg = 1; break;
	}
    }
    if (errflg)
	usage(argv[0]);
    load_ids();
    if (optind < argc) {
	while (optind < argc) {
	    int i = strtoul(argv[optind], &s, 16);
	    if ((argv[optind] == '\0') || (*s != '\0'))
		usage(argv[0]);
	    if (dump_basic(i) != 0)
		return EXIT_FAILURE;
	    optind++;
	}
	return EXIT_SUCCESS;
    }
    return dump_basic(-1);
}
