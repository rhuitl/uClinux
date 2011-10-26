/*======================================================================

    A utility for reconfiguring PnP BIOS devices

    setpnp.c 1.7 2000/06/12 21:34:19

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

    setpnp [-b] [device #] [resource list]
    setpnp [-b] [device #] {on|off}

    The device number is a two-digit hex string.  The resource list
    consists of a series of resource names and values.  Four resource
    names are available: "io", "mem", "irq", and "dma".  Values can
    either be single numbers or dash-delimited ranges.  More than one
    value can be listed in a single argument, separated by commas.
    
    For example:

    setpnp 0d irq 3 io 0x02f8-0x02ff

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

#define NRSRC	4
#define NBASE	8
#define R_IO	0
#define R_MEM	1
#define R_IRQ	2
#define R_DMA	3

struct rsrc_list {
    int		nr[NRSRC];
    u_long	base[NRSRC][NBASE];
    u_long	len[NRSRC][NBASE];
};

static const char *rsrc_type[] = { "io", "mem", "irq", "dma" };

/*====================================================================*/

static char *update_chain(u_char *buf, int nr, struct rsrc_list *res)
{
    union pnp_resource *p = (union pnp_resource *)buf;
    int tag = 0, sz, nu[4];
    u_long base, len;
    
    nu[0] = nu[1] = nu[2] = nu[3] = 0;
    while (((u_char *)p < buf+nr) && (tag != PNP_RES_SMTAG_END)) {
	if (p->lg.tag & PNP_RES_LARGE_ITEM) {
	    union pnp_large_resource *r = &p->lg.d;
	    tag = p->lg.tag & ~PNP_RES_LARGE_ITEM;
	    sz = flip16(p->lg.sz) + 2;
	    switch (tag) {
	    case PNP_RES_LGTAG_MEM:
		if (res->nr[R_MEM] > nu[R_MEM]) {
		    base = res->base[R_MEM][nu[R_MEM]++];
		    len = res->len[R_MEM][nu[R_MEM]++];
		    r->mem.min = r->mem.max = flip16(base >> 8);
		    r->mem.len = flip16(len);
		}
		break;
	    case PNP_RES_LGTAG_MEM32:
		if (res->nr[R_MEM] > nu[R_MEM]) {
		    base = res->base[R_MEM][nu[R_MEM]++];
		    len = res->len[R_MEM][nu[R_MEM]++];
		    r->mem32.min = r->mem32.max = flip32(base);
		    r->mem32.len = flip32(len);
		}
		break;
	    case PNP_RES_LGTAG_MEM32_FIXED:
		if (res->nr[R_MEM] > nu[R_MEM]) {
		    base = res->base[R_MEM][nu[R_MEM]];
		    len = res->len[R_MEM][nu[R_MEM]++];
		    r->mem32_fixed.base = flip32(base);
		    r->mem32_fixed.len = flip32(len);
		}
		break;
	    }
	} else {
	    union pnp_small_resource *r = &p->sm.d;
	    tag = (p->sm.tag >> 3); sz = (p->sm.tag & 7);
	    switch (tag) {
	    case PNP_RES_SMTAG_IRQ:
		if (res->nr[R_IRQ] > nu[R_IRQ]) {
		    base = res->base[R_IRQ][nu[R_IRQ]++];
		    r->irq.mask = base ? flip16(1<<base) : 0;
		}
		break;
	    case PNP_RES_SMTAG_DMA:
		if (res->nr[R_DMA] > nu[R_DMA]) {
		    base = res->base[R_DMA][nu[R_DMA]++];
		    r->dma.mask = base ? flip16(1<<base) : 0;
		}
		break;
	    case PNP_RES_SMTAG_IO:
		if (res->nr[R_IO] > nu[R_IO]) {
		    base = res->base[R_IO][nu[R_IO]];
		    len = res->len[R_IO][nu[R_IO]++];
		    r->io.min = r->io.max = flip16(base);
		    r->io.len = len;
		}
		break;
	    case PNP_RES_SMTAG_IO_FIXED:
		if (res->nr[R_IO] > nu[R_IO]) {
		    base = res->base[R_IO][nu[R_IO]++];
		    len = res->len[R_IO][nu[R_IO]++];
		    r->io_fixed.base = flip16(base);
		    r->io_fixed.len = len;
		}
		break;
	    }
	}
	(u_char *)p += sz + 1;
    }
    return (u_char *)p;
}

static int update_resources(int num, struct rsrc_list *res)
{
    char fn[40];
    u_char buf[4096];
    int fd, nr, nw;
    
    if (access("/proc/bus/pnp", F_OK) != 0) {
	fprintf(stderr, "lspnp: /proc/bus/pnp not available\n");
	return EXIT_FAILURE;
    }
    
    sprintf(fn, "/proc/bus/pnp/%s%02x", (boot ? "boot/" : ""), num);
    fd = open(fn, O_RDWR);
    nr = read(fd, buf, sizeof(buf));
    if (nr <= 0) {
	perror("read failed");
	return EXIT_FAILURE;
    }
    
    update_chain(buf, nr, res);
    nw = write(fd, buf, nr);
    close(fd);
    if (nr != nw) {
	perror("write failed");
	return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static int reset_resources(int num)
{
    char fn[40];
    u_char buf[4096];
    int fd, nr, nw;
    
    if (access("/proc/bus/pnp", F_OK) != 0) {
	fprintf(stderr, "lspnp: /proc/bus/pnp not available\n");
	return EXIT_FAILURE;
    }
    sprintf(fn, "/proc/bus/pnp/boot/%02x", num);
    fd = open(fn, O_RDONLY);
    nr = read(fd, buf, sizeof(buf));
    close(fd);
    if (nr <= 0) {
	perror("read failed");
	return EXIT_FAILURE;
    }
    sprintf(fn, "/proc/bus/pnp/%02x", num);
    fd = open(fn, O_WRONLY);
    nw = write(fd, buf, nr);
    close(fd);
    if (nr != nw) {
	perror("write failed");
	return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

/*====================================================================*/

static int parse_resources(char *argv[], int argc,
			   struct rsrc_list *res)
{
    int i, j;
    u_long base, len;
    char *s, *t;
    
    for (i = 0; i < argc; i += 2) {
	for (j = 0; j < NRSRC; j++)
	    if (strcmp(rsrc_type[j], argv[i]) == 0) break;
	if (j == NRSRC) {
	    fprintf(stderr, "bad resource type: '%s'\n", argv[i]);
	    return EXIT_FAILURE;
	}
	s = strtok(argv[i+1], ", \t");
	while (s) {
	    base = strtoul(s, &t, 0);
	    len = ((*t == '-') ? strtoul(t+1, &t, 0)-base+1 : 1);
	    if ((*s == '\0') || (*t != '\0')) {
		fprintf(stderr, "bad resource argument: '%s'\n", t);
		return EXIT_FAILURE;
	    }
	    res->base[j][res->nr[j]] = base;
	    res->len[j][res->nr[j]++] = len;
	    s = strtok(NULL, ", \t");
	}
    }
    return EXIT_SUCCESS;
}

/*====================================================================*/

void usage(char *name)
{
    fprintf(stderr, "usage: %s [-b] [device #] [resources ...]\n"
	    "    or %s [-b] [device #] {on|off}\n", name, name);
    exit(EXIT_FAILURE);
}
    
int main(int argc, char *argv[])
{
    int i, optch, errflg = 0;
    static struct rsrc_list res;
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
    if (errflg || (optind == argc))
	usage(argv[0]);
    
    i = strtoul(argv[optind], &s, 16);
    if ((argv[optind] == '\0') || (*s != '\0'))
	usage(argv[0]);
    optind++;

    /* Special commands */
    if (argc == optind+1) {
	if (strcmp(argv[optind], "off") == 0) {
	    res.nr[0] = res.nr[1] = res.nr[2] = res.nr[3] = 7;
	    optind++;
	} else if (strcmp(argv[optind], "on") == 0) {
	    return reset_resources(i);
	} else {
	    usage(argv[0]);
	}
    } else if (argc == optind)
	usage(argv[0]);
    
    if ((argc - optind) % 2)
	usage(argv[0]);
    if (parse_resources(argv+optind, argc-optind, &res) == 0)
	return update_resources(i, &res);
    return EXIT_FAILURE;
}
