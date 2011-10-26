/*======================================================================

    Dump ExCA compatible PCMCIA bridge registers

    dump_exca.c 1.4 2000/06/12 21:34:19

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
    
======================================================================*/

#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "i82365.h"
#include "cirrus.h"
#include "vg468.h"
#include "yenta.h"

/*====================================================================*/

typedef struct proc_exca {
    union {
	u_char	b[80];
	u_short	w[40];
    } reg;
    u_char	ext[64];
} proc_exca;

#define IS_CIRRUS	0x01
#define IS_VG468	0x02
#define IS_VG469	0x04

typedef struct proc_info {
    char	type[32];
    u_int	flags;
    int		psock;
    u_char	bus;
    u_char	devfn;
    u_char	cardbus;
} proc_info;

static proc_exca *load_exca(char *fn)
{
    FILE *f = fopen(fn, "r");
    static proc_exca ex;
    char s[50];
    int i, j;
    
    if (!f) return NULL;
    memset(&ex, 0, sizeof ex); 
    for (i = 0; (i < 80) && !feof(f); i += 16) {
	fgets(s, 49, f);
	if (strlen(s) < 48) break;
	for (j = 0; j < 16; j++)
	    ex.reg.b[i+j] = strtoul(s + 3*j, NULL, 16);
    }
    for (i = 0; (i < 64) && !feof(f); i += 16) {
	fgets(s, 49, f);
	if (strlen(s) < 48) break;
	for (j = 0; j < 16; j++)
	    ex.ext[i+j] = strtoul(s + 3*j, NULL, 16);
    }
    fclose(f);
    return &ex;
}

#define NTAG 5
char *tag[] = { "type:", "psock:", "bus:", "devfn:", "cardbus:" };

static proc_info *load_info(char *fn)
{
    FILE *f = fopen(fn, "r");
    static proc_info in;
    char s[50];
    u_int i, a, b;
    
    if (!f) return NULL;
    memset(&in, 0, sizeof in);
    while (!feof(f)) {
	fgets(s, 49, f);
	for (i = 0; i < NTAG; i++)
	    if (strncmp(s, tag[i], strlen(tag[i])) == 0) break;
	switch (i) {
	case 0: strcpy(in.type, s+10); break;
	case 1: in.psock = strtoul(s+10, NULL, 10); break;
	case 2: in.bus = strtoul(s+10, NULL, 16); break;
	case 3:
	    sscanf(s+10, "%02x.%d", &a, &b);
	    in.devfn = (a<<3) | b;
	    break;
	case 4: in.cardbus = strtoul(s+10, NULL, 16);
	}
    }
    if (strstr(in.type, "Cirrus"))
	in.flags |= IS_CIRRUS;
    if (strstr(in.type, "VG-468"))
	in.flags |= IS_VG468;
    if (strstr(in.type, "VG-469"))
	in.flags |= IS_VG469;
    fclose(f);
    return &in;
}

/*====================================================================*/

static void dump_status(proc_exca *ex)
{
    int v = ex->reg.b[I365_STATUS];
    printf("  Interface status = 0x%02x\n   ", v);
    if (v & I365_CS_BVD1) printf(" [bvd1/stschg]");
    if (v & I365_CS_BVD2) printf(" [bvd2/spkr]");
    if (v & I365_CS_DETECT) printf(" [detect]");
    if (v & I365_CS_WRPROT) printf(" [wrprot]");
    if (v & I365_CS_READY) printf(" [ready]");
    if (v & I365_CS_POWERON) printf(" [poweron]");
    if (v & I365_CS_GPI) printf(" [gpi]");
    printf("\n");
}

static void dump_power(proc_exca *ex)
{
    int v = ex->reg.b[I365_POWER];
    printf("  Power control = 0x%02x\n   ", v);
    if (v & I365_PWR_OUT) printf(" [output]");
    if (!(v & I365_PWR_NORESET)) printf(" [resetdrv]");
    if (v & I365_PWR_AUTO) printf(" [auto]");
    switch (v & I365_VCC_MASK) {
    case I365_VCC_5V:
	printf(" [Vcc=5v]"); break;
    case I365_VCC_3V:
	printf(" [Vcc=3.3v]"); break;
    case 0:
	printf(" [Vcc off]"); break;
    }
    switch (v & I365_VPP1_MASK) {
    case I365_VPP1_5V:
	printf(" [Vpp=5v]"); break;
    case I365_VPP1_12V:
	printf(" [Vpp=12v]"); break;
    case 0:
	printf(" [Vpp off]"); break;
    }
    printf("\n");
}

static void dump_intctl(proc_exca *ex)
{
    int v = ex->reg.b[I365_INTCTL];
    printf("  Interrupt and general control = 0x%02x\n   ", v);
    if (v & I365_RING_ENA) printf(" [ring ena]");
    if (!(v & I365_PC_RESET)) printf(" [reset]");
    if (v & I365_PC_IOCARD) printf(" [iocard]");
    if (v & I365_INTR_ENA) printf(" [intr ena]");
    printf(" [irq=%d]\n", v & I365_IRQ_MASK);
}

static void dump_csc(proc_exca *ex)
{
    int v = ex->reg.b[I365_CSC];
    if (!v) return;
    printf("  Card status change = 0x%02x\n   ", v);
    if (v & I365_CSC_BVD1) printf(" [bvd1/stschg]");
    if (v & I365_CSC_BVD2) printf(" [bvd2]");
    if (v & I365_CSC_DETECT) printf(" [detect]");
    if (v & I365_CSC_READY) printf(" [ready]");
    if (v & I365_CSC_GPI) printf(" [gpi]");
    printf("\n");
}

static void dump_cscint(proc_exca *ex)
{
    int v = ex->reg.b[I365_CSCINT];
    printf("  Card status change interrupt control = 0x%02x\n", v);
    printf("   ");
    if (v & I365_CSC_BVD1) printf(" [bvd1/stschg]");
    if (v & I365_CSC_BVD2) printf(" [bvd2]");
    if (v & I365_CSC_DETECT) printf(" [detect]");
    if (v & I365_CSC_READY) printf(" [ready]");
    printf(" [irq=%d]\n", v >> 4);
}

static void dump_genctl(proc_exca *ex)
{
    int v = ex->reg.b[I365_GENCTL];
    printf("  Card detect and general control = 0x%02x\n   ", v);
    if (v & I365_CTL_16DELAY) printf(" [16delay]");
    if (v & I365_CTL_RESET) printf(" [reset]");
    if (v & I365_CTL_GPI_ENA) printf(" [gpi ena]");
    if (v & I365_CTL_GPI_CTL) printf(" [gpi ctl]");
    if (v & I365_CTL_RESUME) printf(" [resume]");
    printf("\n");
}

static void dump_gblctl(proc_exca *ex)
{
    int v = ex->reg.b[I365_GBLCTL];
    if (!v) return;
    printf("  Global control = 0x%02x\n   ", v);
    if (v & I365_GBL_PWRDOWN) printf(" [pwrdown]");
    if (v & I365_GBL_CSC_LEV) printf(" [csc level]");
    if (v & I365_GBL_WRBACK) printf(" [wrback]");
    if (v & I365_GBL_IRQ_0_LEV) printf(" [irq A level]");
    if (v & I365_GBL_IRQ_1_LEV) printf(" [irq B level]");
    printf("\n");
}

/*====================================================================*/

/* Cirrus-specific registers */

static void dump_misc1(proc_exca *ex)
{
    int v = ex->reg.b[PD67_MISC_CTL_1];
    printf("  Misc control 1 = 0x%02x\n   ", v);
    if (v & PD67_MC1_5V_DET) printf(" [5v detect]");
    if (v & PD67_MC1_VCC_3V) printf(" [Vcc 3.3v]");
    if (v & PD67_MC1_PULSE_MGMT) printf(" [pulse mgmt]");
    if (v & PD67_MC1_PULSE_IRQ) printf(" [pulse irq]");
    if (v & PD67_MC1_SPKR_ENA) printf(" [spkr]");
    if (v & PD67_MC1_INPACK_ENA) printf(" [inpack]");
    printf("\n");
}

static void dump_misc2(proc_exca *ex)
{
    int v = ex->reg.b[PD67_MISC_CTL_2];
    printf("  Misc control 2 = 0x%02x\n   ", v);
    if (v & PD67_MC2_FREQ_BYPASS) printf(" [freq bypass]");
    if (v & PD67_MC2_DYNAMIC_MODE) printf(" [dynamic mode]");
    if (v & PD67_MC2_SUSPEND) printf(" [suspend]");
    if (v & PD67_MC2_5V_CORE) printf(" [5v core]");
    if (v & PD67_MC2_LED_ENA) printf(" [LED ena]");
    if (v & PD67_MC2_3STATE_BIT7) printf(" [3state bit 7]");
    if (v & PD67_MC2_DMA_MODE) printf(" [DMA mode]");
    if (v & PD67_MC2_IRQ15_RI) printf(" [irq 15 is RI]");
    printf("\n");
}

static void print_time(char *s, int v)
{
    printf("%s = %d", s, v & PD67_TIME_MULT);
    switch (v & PD67_TIME_SCALE) {
    case PD67_TIME_SCALE_16:
	printf(" [*16]"); break;
    case PD67_TIME_SCALE_256:
	printf(" [*256]"); break;
    case PD67_TIME_SCALE_4096:
	printf(" [*4096]"); break;
    }
}

static void dump_timing(proc_exca *ex, int i)
{
    printf("  Timing set %d: ", i);
    print_time("setup", ex->reg.b[PD67_TIME_SETUP(i)]);
    print_time(", command", ex->reg.b[PD67_TIME_CMD(i)]);
    print_time(", recovery", ex->reg.b[PD67_TIME_RECOV(i)]);
    printf("\n");
}

void dump_ext(proc_exca *ex)
{
    u_char v;
    printf("  Extension registers:");
    printf("    ");
    v = ex->ext[PD67_DATA_MASK0];
    printf("mask 0 = 0x%02x", v);
    v = ex->reg.b[PD67_DATA_MASK1];
    printf(", mask 1 = 0x%02x", v);
    v = ex->reg.b[PD67_DMA_CTL];
    printf(", DMA ctl = 0x%02x", v);
    switch (v & PD67_DMA_MODE) {
    case PD67_DMA_OFF:
	printf(" [off]"); break;
    case PD67_DMA_DREQ_INPACK:
	printf(" [dreq is inpack]"); break;
    case PD67_DMA_DREQ_WP:
	printf(" [dreq is wp]"); break;
    case PD67_DMA_DREQ_BVD2:
	printf(" [dreq is bvd2]"); break;
    }
    if (v & PD67_DMA_PULLUP)
	printf(" [pullup]");
    printf("\n");
}

/*====================================================================*/

/* Vadem-specific registers */

static void dump_vsense(proc_exca *ex)
{
    int v = ex->reg.b[VG469_VSENSE];
    printf("  Card voltage sense = 0x%02x\n   ", v);
    if (v & VG469_VSENSE_A_VS1) printf(" [a_vs1]");
    if (v & VG469_VSENSE_A_VS2) printf(" [a_vs2]");
    if (v & VG469_VSENSE_B_VS1) printf(" [b_vs1]");
    if (v & VG469_VSENSE_B_VS2) printf(" [b_vs2]");
    printf("\n");
}

static void dump_vselect(proc_exca *ex)
{
    int v = ex->reg.b[VG469_VSELECT];
    printf("  Card voltage select = 0x%02x\n   ", v);
    switch (v & VG469_VSEL_VCC) {
    case 0: printf(" [Vcc=5v]"); break;
    case 1: printf(" [Vcc=3.3v]"); break;
    case 2: printf(" [Vcc=X.Xv]"); break;
    case 3: printf(" [Vcc=3.3v]"); break;
    }
    switch (v & VG469_VSEL_MAX) {
    case 0: printf(" [Vmax=5v]"); break;
    case 1: printf(" [Vmax=3.3v]"); break;
    case 2: printf(" [Vmax=X.Xv]"); break;
    case 3: printf(" [Vcc=3.3v]"); break;
    }
    if (v & VG469_VSEL_EXT_STAT) printf(" [extended]");
    if (v & VG469_VSEL_EXT_BUS) printf(" [buffer]");
    if (v & VG469_VSEL_MIXED)
	printf(" [mixed]");
    else
	printf(" [5v only]");
    if (v & VG469_VSEL_ISA)
	printf(" [3v bus]");
    else
	printf(" [5v bus]");
    printf("\n");
}

static void dump_control(proc_exca *ex)
{
    int v = ex->reg.b[VG468_CTL];
    printf("  Control register = 0x%02x\n   ", v);
    if (v & VG468_CTL_SLOW) printf(" [slow]");
    if (v & VG468_CTL_ASYNC) printf(" [async]");
    if (v & VG468_CTL_TSSI) printf(" [tri-state]");
    if (v & VG468_CTL_DELAY) printf(" [debounce]");
    if (v & VG469_CTL_STRETCH) printf(" [stretch]");
    if (v & VG468_CTL_INPACK) printf(" [inpack]");
    if (v & VG468_CTL_POLARITY)
	printf(" [active high]");
    else
	printf(" [active low]");
    if (v & VG468_CTL_COMPAT) printf(" [compat]");
    printf("\n");
}

static void dump_misc(proc_exca *ex)
{
    int v = ex->reg.b[VG468_MISC];
    printf("  Misc register = 0x%02x\n   ", v);
    if (v & VG468_MISC_GPIO) printf(" [gpio]");
    if (v & VG468_MISC_DMAWSB) printf(" [DMA ws]");
    if (v & VG469_MISC_LEDENA) printf(" [LED ena]");
    if (v & VG468_MISC_VADEMREV) printf(" [Vadem rev]");
    if (v & VG468_MISC_UNLOCK) printf(" [unlock]");
    printf("\n");
}

static void dump_ext_mode(proc_exca *ex, proc_info *in)
{
    int v = ex->reg.b[VG469_EXT_MODE];
    printf("  Extended mode %c = 0x%02x\n   ",
	   (in->psock ? 'B' : 'A'), v);
    if (in->psock) {
	if (v & VG469_MODE_B_3V) printf(" [3.3v sock B]");
    } else {
	if (v & VG469_MODE_INT_SENSE) printf(" [int sense]");
	if (v & VG469_MODE_CABLE) printf(" [cable mode]");
	if (v & VG469_MODE_COMPAT) printf(" [DF compat]");
	if (v & VG469_MODE_TEST) printf(" [test]");
	if (v & VG469_MODE_RIO) printf(" [RIO to INTR]");
    }
    printf("\n");
}

/*====================================================================*/

static void dump_memwin(proc_exca *ex, proc_info *in, int w)
{
    u_int start, stop, off;
    char flags[50];

    start = ex->reg.w[(I365_MEM(w)+I365_W_START)>>1];
    stop = ex->reg.w[(I365_MEM(w)+I365_W_STOP)>>1];
    off = ex->reg.w[(I365_MEM(w)+I365_W_OFF)>>1];

    if (ex->reg.b[I365_ADDRWIN] & I365_ENA_MEM(w))
	strcpy(flags, " [on]");
    else
	strcpy(flags, " [off]");
    if (start & I365_MEM_16BIT)
	strcat(flags, " [16bit]");
    else
	strcat(flags, " [8bit]");
    if (in->flags & IS_CIRRUS) {
	if (stop & I365_MEM_WS1)
	    strcat(flags, " [time1]");
	else
	    strcat(flags, " [time0]");
    } else {
	if (start & I365_MEM_0WS) strcat(flags, " [0ws]");
	if (stop & I365_MEM_WS1) strcat(flags, " [ws1]");
	if (stop & I365_MEM_WS0) strcat(flags, " [ws0]");
    }
    if (off & I365_MEM_WRPROT) strcat(flags, " [wrprot]");
    if (off & I365_MEM_REG) strcat(flags, " [reg]");

    start = (start & 0x0fff) << 12;
    stop = ((stop & 0x0fff) << 12) + 0x0fff;
    off = (off & 0x3fff) << 12;
    start += ex->reg.b[CB_MEM_PAGE(w)]<<24;
    stop += ex->reg.b[CB_MEM_PAGE(w)]<<24;
    off = (off+start) & 0x3ffffff;
    printf("  memory %d: 0x%04x-0x%04x @ 0x%08x%s\n",
	   w, off, off+stop-start, start, flags);
}

static void dump_iowin(proc_exca *ex, proc_info *in, int w)
{
    u_short ctl, off = 0;
    if (in->flags & IS_CIRRUS)
	off = ex->reg.w[PD67_IO_OFF(w)>>1];
    printf("  io %d: 0x%04x-0x%04x", w,
	   off + ex->reg.w[(I365_IO(w)+I365_W_START)>>1],
	   off + ex->reg.w[(I365_IO(w)+I365_W_STOP)>>1]);
    if (off)
	printf(" @ 0x%04x", ex->reg.w[(I365_IO(w)+I365_W_START)>>1]);

    if (ex->reg.b[I365_ADDRWIN] & I365_ENA_IO(w))
	printf(" [on]");
    else
	printf(" [off]");
    
    ctl = ex->reg.b[I365_IOCTL];
    if (in->flags & IS_CIRRUS) {
	if (ctl & I365_IOCTL_WAIT(w))
	    printf(" [time1]");
	else
	    printf(" [time0]");
    } else {
	if (ctl & I365_IOCTL_WAIT(w)) printf(" [wait]");
	if (ctl & I365_IOCTL_0WS(w)) printf(" [0ws]");
    }
    if (ctl & I365_IOCTL_IOCS16(w)) printf(" [iocs16]");
    if (ctl & I365_IOCTL_16BIT(w))
	printf(" [16bit]\n");
    else
	printf(" [8bit]\n");
}

/*====================================================================*/

void dump_sock(proc_exca *ex, proc_info *in)
{
    int i;
    printf("  Identification and revision = 0x%02x\n",
	   ex->reg.b[I365_IDENT]);
    if (in->flags & IS_CIRRUS)
	printf("  Chip information = 0x%02x\n",
	       ex->reg.b[PD67_CHIP_INFO]);
    dump_status(ex);
    dump_power(ex);
    if (in->flags & IS_VG469)
	dump_vselect(ex);
    dump_intctl(ex);
    dump_csc(ex);
    dump_cscint(ex);

    if (in->flags & IS_CIRRUS) {
	dump_misc1(ex);
	dump_misc2(ex);
    } else {
	dump_genctl(ex);
	dump_gblctl(ex);
    }

    if (in->flags & IS_VG469) {
	dump_vsense(ex);
	dump_ext_mode(ex, in);
    }
    if ((in->flags & IS_VG468) || (in->flags & IS_VG469)) {
	dump_control(ex);
	dump_misc(ex);
    }
    
    for (i = 0; i < 5; i++)
	dump_memwin(ex, in, i);
    for (i = 0; i < 2; i++)
	dump_iowin(ex, in, i);
    
    if (in->flags & IS_CIRRUS) {
	for (i = 0; i < 2; i++)
	    dump_timing(ex, i);
	dump_ext(ex);
    }
    printf("\n");
} /* dump_sock */

/*====================================================================*/

int main(int argc, char *argv[])
{
    char fn[100];
    int i;
    proc_exca *ex;
    proc_info *in;

    if (access("/proc/bus/pccard", R_OK) != 0)
	fprintf(stderr, "/proc/bus/pccard does not exist!\n");
    for (i = 0; ; i++) {
	sprintf(fn, "/proc/bus/pccard/%02d/exca", i);
	if (access(fn, R_OK) != 0)
	    break;
	ex = load_exca(fn);
	sprintf(fn, "/proc/bus/pccard/%02d/info", i);
	in = load_info(fn);
	printf("Socket %d:\n", i);
	dump_sock(ex, in);
    }
    return 0;
}
