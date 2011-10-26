/*======================================================================

    Register dump for the Databook TCIC-2 controller family

    dump_tcic.c 1.22 2001/06/04 23:31:12

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

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __MSDOS__

#include <dos.h>
typedef unsigned char u_char;
typedef unsigned short u_short;
#define INB(a) inportb(a)
#define OUTB(d, a) outportb(a, d)
#define INW(a) inport(a)
#define OUTW(d, a) outport(a, d)

#else /* __MSDOS__ */

#include <sys/types.h>
#ifdef __GLIBC__
#include <sys/io.h>
#else
#include <asm/io.h>
#endif
#include <unistd.h>
#define INB(a) inb(a)
#define OUTB(d, a) outb(d, a)
#define INW(a) inw(a)
#define OUTW(d, a) outw(d, a)

#endif /* __MSDOS__ */

#include "tcic.h"

/*====================================================================*/

static int tcic_base = TCIC_BASE;

#define tcic_getb(reg) INB(tcic_base+reg)
#define tcic_getw(reg) INW(tcic_base+reg)
#define tcic_setb(reg, data) OUTB(data, tcic_base+reg)
#define tcic_setw(reg, data) OUTW(data, tcic_base+reg)

static void tcic_setl(u_char reg, u_long data)
{
    OUTW(data & 0xffff, tcic_base+reg);
    OUTW(data >> 16, tcic_base+reg+2);
}

#if 0
static u_char tcic_aux_getb(u_short reg)
{
    u_char mode = (tcic_getb(TCIC_MODE) & TCIC_MODE_PGMMASK) | reg;
    tcic_setb(TCIC_MODE, mode);
    return tcic_getb(TCIC_AUX);
}
#endif

static u_short tcic_aux_getw(u_short reg)
{
    u_char mode = (tcic_getb(TCIC_MODE) & TCIC_MODE_PGMMASK) | reg;
    tcic_setb(TCIC_MODE, mode);
    return tcic_getw(TCIC_AUX);
}

/*====================================================================*/

int tcic_probe(void)
{
    int sock;

    printf("Databook TCIC-2 probe: ");
    sock = 0;
    
    tcic_setw(TCIC_ADDR, 0);
    if (tcic_getw(TCIC_ADDR) == 0) {
	tcic_setw(TCIC_ADDR, 0xc3a5);
	if (tcic_getw(TCIC_ADDR) == 0xc3a5) sock = 2;
    }
    
    if (sock == 0)
	printf("not found.\n");
    else
	printf("%d sockets\n", sock);
    
    return sock;
} /* tcic_probe */

/*====================================================================*/

void dump_sctrl(int ns)
{
    u_char v;
    tcic_setl(TCIC_ADDR, (0 << TCIC_ADDR_SS_SHFT));
    v = tcic_getb(TCIC_SCTRL);
    printf("  Socket control = %#2.2x\n", v);
    printf("   ");
    if (v & TCIC_SCTRL_RESET) printf(" [RESET]");
    if (v & TCIC_SCTRL_EDCSUM) printf(" [EDCSUM]");
    switch (v & TCIC_SCTRL_INCMODE) {
    case TCIC_SCTRL_INCMODE_HOLD:
	printf(" [BYTE HOLD]"); break;
    case TCIC_SCTRL_INCMODE_WORD:
	printf(" [WORD HOLD]"); break;
    case TCIC_SCTRL_INCMODE_REG:
	printf(" [WORD INC]"); break;
    case TCIC_SCTRL_INCMODE_AUTO:
	printf(" [AUTO INC]"); break;
    }
    if (v & TCIC_SCTRL_ENA) printf(" [ENA]");
    printf("\n");
}

void dump_sstat(int s)
{
    u_char v;
    tcic_setl(TCIC_ADDR, (s << TCIC_ADDR_SS_SHFT));
    v = tcic_getb(TCIC_SSTAT);
    printf("  Socket status = %#2.2x\n", v);
    printf("   ");
    if (v & TCIC_SSTAT_CD) printf(" [CD]");
    if (v & TCIC_SSTAT_WP) printf(" [WP]");
    if (v & TCIC_SSTAT_RDY) printf(" [RDY]");
    if (v & TCIC_SSTAT_LBAT1) printf(" [LBAT1]");
    if (v & TCIC_SSTAT_LBAT2) printf(" [LBAT2]");
    if (v & TCIC_SSTAT_PROGTIME) printf(" [PROGTIME]");
    if (v & TCIC_SSTAT_10US) printf(" [10us]");
    if (v & TCIC_SSTAT_6US) printf(" [6us]");
    printf("\n");
}

void dump_mode(int s)
{
    u_char v;
    tcic_setl(TCIC_ADDR, (s << TCIC_ADDR_SS_SHFT));
    v = tcic_getb(TCIC_MODE);
    printf("  Mode register = %#2.2x\n", v);
    printf("   ");
    if ((v & TCIC_MODE_PGMMASK) == 0)
	printf(" [NORMAL]");
    else {
	if (v & TCIC_MODE_PGMWORD) printf(" [WORD]");
	if (v & TCIC_MODE_PGMDBW) printf(" [DBW]");
	if (v & TCIC_MODE_PGMCE) printf(" [CE]");
	if (v & TCIC_MODE_PGMRD) printf(" [RD]");
	if (v & TCIC_MODE_PGMWR) printf(" [WR]");
    }
    printf("\n");
}

void dump_pwr(int s)
{
    u_char v = tcic_getb(TCIC_PWR);
    printf("  Power control = %#2.2x\n", v);
    printf("   ");
    
    if (v & TCIC_PWR_CLIMSTAT) printf(" [CLIMSTAT]");
    if (v & TCIC_PWR_CLIMENA) printf(" [CLIMENA]");
    if (v & TCIC_PWR_VCC(s)) {
	if (v & TCIC_PWR_VPP(s))
	    printf(" [Vcc=5V] [Vpp OFF]");
	else
	    printf(" [Vcc=5V] [Vpp=5V]");
    }
    else {
	if (v & TCIC_PWR_VPP(s))
	    printf(" [Vcc=5V] [Vpp=12V]");
	else
	    printf(" [Vcc OFF] [Vpp OFF]");
    }
    printf("\n");
}

void dump_icsr(int s)
{
    u_char v;
    tcic_setl(TCIC_ADDR, (s << TCIC_ADDR_SS_SHFT));
    v = tcic_getb(TCIC_ICSR);
    printf("  Interrupt control/status = %#2.2x\n", v);
    printf("   ");
    if (v & TCIC_ICSR_IOCHK) printf(" [IOCHK]");
    if (v & TCIC_ICSR_CDCHG) printf(" [CDCHG]");
    if (v & TCIC_ICSR_ERR) printf(" [ERR]");
    if (v & TCIC_ICSR_PROGTIME) printf(" [PROGTIME]");
    if (v & TCIC_ICSR_ILOCK) printf(" [ILOCK]");
    if (v & TCIC_ICSR_STOPCPU) printf(" [STOPCPU]");
    printf("\n");
}

void dump_iena(int s)
{
    u_char v;
    tcic_setl(TCIC_ADDR, (s << TCIC_ADDR_SS_SHFT));
    v = tcic_getb(TCIC_IENA);
    printf("  Interrupt enable = %#2.2x\n", v);
    printf("   ");
    switch (v & TCIC_IENA_CFG_MASK) {
    case TCIC_IENA_CFG_OFF:
	printf(" [OFF]"); break;
    case TCIC_IENA_CFG_OD:
	printf(" [OD]"); break;
    case TCIC_IENA_CFG_LOW:
	printf(" [LOW]"); break;
    case TCIC_IENA_CFG_HIGH:
	printf(" [HIGH]"); break;
    }
    if (v & TCIC_IENA_ILOCK) printf(" [ILOCK]");
    if (v & TCIC_IENA_PROGTIME) printf(" [PROGTIME]");
    if (v & TCIC_IENA_ERR) printf(" [ERR]");
    if (v & TCIC_IENA_CDCHG) printf(" [CDCHG]");
    printf("\n");
}

void dump_wctl(int s)
{
    u_short v;
    tcic_setl(TCIC_ADDR, (s << TCIC_ADDR_SS_SHFT));
    v = tcic_aux_getw(TCIC_AUX_WCTL);
    printf("  Wait control = %#4.4x\n", v);
    printf("   ");
    if (v & TCIC_WCTL_LCD) printf(" [LCD]");
    if (v & TCIC_WCTL_LWP) printf(" [LWP]");
    if (v & TCIC_WCTL_LRDY) printf(" [LRDY]");
    if (v & TCIC_WCTL_LLBAT1) printf(" [LLBAT1]");
    if (v & TCIC_WCTL_CE) printf(" [CE]");
    if (v & TCIC_WCTL_RD) printf(" [RD]");
    if (v & TCIC_WCTL_WR) printf(" [WR]");
    if (v & TCIC_WAIT_SRC) printf(" [SRC]");
    if (v & TCIC_WAIT_SENSE) printf(" [SENSE]");
    if (v & TCIC_WAIT_ASYNC) printf(" [ASYNC]");
    printf(" [COUNT=%d]\n", v & TCIC_WAIT_COUNT_MASK);
}

void dump_syscfg(void)
{
    u_short v = tcic_aux_getw(TCIC_AUX_SYSCFG);
    printf("  System configuration = %#4.4x\n", v);
    printf("   ");
    if (v & TCIC_SYSCFG_ACC) printf(" [ACC]");
    if (v & TCIC_SYSCFG_AUTOBUSY) printf(" [AUTOBUSY]");
    if (v & TCIC_SYSCFG_MPSENSE) printf(" [MPSENSE]");
    switch ((v & TCIC_SYSCFG_MPSEL_MASK) >> TCIC_SYSCFG_MPSEL_SHFT) {
    case 0:
	printf(" [/MULTI OFF]"); break;
    case 1:
	printf(" [/MULTI CLOCK]"); break;
    case 2:
	printf(" [/MULTI INPUT]"); break;
    case 3:
	printf(" [/MULTI OUTPUT]"); break;
    case 5:
	printf(" [/MULTI RI]"); break;
    }
    if (v & TCIC_SYSCFG_NOPDN) printf(" [NOPDN]");
    if (v & TCIC_SYSCFG_ICSXB) printf(" [ICSXB]");
    if (v & TCIC_SYSCFG_MCSXB) printf(" [MCSXB]");
    if (v & TCIC_SYSCFG_IO1723) printf(" [IO1723]");
    if (v & TCIC_SYSCFG_MCSFULL) printf(" [MCSFULL]");
    switch (v & TCIC_SYSCFG_IRQ_MASK) {
    case 0:
    case 1:
	printf(" [SKTIRQ]\n");
	break;
    case 3: case 4: case 5: case 6:
    case 7: case 10: case 14:
	printf(" [irq = %d]\n", v & TCIC_SYSCFG_IRQ_MASK);
	break;
    default:
	printf(" [bad irq]\n");
	break;
    }
}

void dump_scf1(int s)
{
    u_short v;
    tcic_setl(TCIC_ADDR, (s << TCIC_ADDR_SS_SHFT)
	      | TCIC_ADDR_INDREG | TCIC_SCF1(s));
    v = tcic_getw(TCIC_DATA);
    printf("  Socket config register 1: %#4.4x\n", v);
    printf("   ");
    if (v & TCIC_SCF1_HD7IDE) printf(" [HD7IDE]");
    if (v & TCIC_SCF1_DELWR) printf(" [DELWR]");
    if (v & TCIC_SCF1_FINPACK) printf(" [FINPACK]");
    if (v & TCIC_SCF1_SPKR) printf(" [SPKR]");
    if (v & TCIC_SCF1_IOSTS) printf(" [IOSTS]");
    switch ((v & TCIC_SCF1_DMA_MASK) >> TCIC_SCF1_DMA_SHIFT) {
    case TCIC_SCF1_DMA_OFF:
	printf(" [DMA OFF]"); break;
    case TCIC_SCF1_DREQ2:
	printf(" [DMA REQ2]"); break;
    }
    if (v & TCIC_SCF1_ATA) printf(" [ATA]");
    if (v & TCIC_SCF1_IRDY) printf(" [IRDY]");
    if (v & TCIC_SCF1_PCVT) printf(" [PCVT]");
    if (v & TCIC_SCF1_IRQOC) printf(" [IRQOC]");
    switch (v & TCIC_SCF1_IRQ_MASK) {
    case 0:
	printf(" [irq off]\n");
    case 1:
	printf(" [SKTIRQ]\n");
	break;
    case 3: case 4: case 5: case 6:
    case 7: case 10: case 14:
	printf(" [irq = %d]\n", v & TCIC_SCF1_IRQ_MASK);
	break;
    default:
	printf(" [bad irq]\n");
	break;
    }
}

void dump_scf2(int s)
{
    u_short v;
    tcic_setl(TCIC_ADDR, (s << TCIC_ADDR_SS_SHFT)
	      | TCIC_ADDR_INDREG | TCIC_SCF2(s));
    v = tcic_getw(TCIC_DATA);
    printf("  Socket config register 2: %#4.4x\n", v);
    printf("   ");
    if (v & TCIC_SCF2_RI) printf(" [RI]");
    if (v & TCIC_SCF2_IDBR) printf(" [IDBR]");
    if (v & TCIC_SCF2_MDBR) printf(" [MDBR]");
    if (v & TCIC_SCF2_MLBAT1) printf(" [MLBAT1]");
    if (v & TCIC_SCF2_MLBAT2) printf(" [MLBAT2]");
    if (v & TCIC_SCF2_MRDY) printf(" [MRDY]");
    if (v & TCIC_SCF2_MWP) printf(" [MWP]");
    if (v & TCIC_SCF2_MCD) printf(" [MCD]");
    printf("\n");
}

/*====================================================================*/

void dump_memwin(int w)
{
    u_short base, mmap, ctl;

    tcic_setw(TCIC_ADDR+2, TCIC_ADR2_INDREG);
    tcic_setw(TCIC_ADDR, TCIC_MWIN(0, w) + TCIC_MCTL_X);
    ctl = tcic_getw(TCIC_DATA);
    tcic_setw(TCIC_ADDR, TCIC_MWIN(0, w) + TCIC_MBASE_X);
    base = tcic_getw(TCIC_DATA);
    tcic_setw(TCIC_ADDR, TCIC_MWIN(0, w) + TCIC_MMAP_X);
    mmap = tcic_getw(TCIC_DATA);
    
    printf("  Memory window %d: base = %#4.4x, mmap = %#4.4x, "
	   "ctl = %#4.4x\n", w, base, mmap, ctl);
    printf("    [SOCK=%d]",
	   (ctl & TCIC_MCTL_SS_MASK) >> TCIC_MCTL_SS_SHFT);
    printf(ctl & TCIC_MCTL_ENA ? " [ON]" : " [OFF]");
    printf(ctl & TCIC_MCTL_B8 ? " [8 Bit]" : " [16 Bit]");
    if (ctl & TCIC_MCTL_QUIET) printf(" [QUIET]");
    if (ctl & TCIC_MCTL_WP) printf(" [WP]");
    if (ctl & TCIC_MCTL_ACC) printf(" [ACC]");
    if (ctl & TCIC_MCTL_KE) printf(" [KE]");
    if (ctl & TCIC_MCTL_EDC) printf(" [EDC]");
    printf(ctl & TCIC_MCTL_WCLK ? " [BCLK]" : " [CCLK]");
    printf(" [ws = %d]", ctl & TCIC_MCTL_WSCNT_MASK);
    if (base & TCIC_MBASE_4K_BIT) printf(" [4K]");
    if (mmap & TCIC_MMAP_REG) printf(" [REG]");
    printf("\n");
}

void dump_iowin(int w)
{
    u_short base, ctl;

    tcic_setw(TCIC_ADDR+2, TCIC_ADR2_INDREG);
    tcic_setw(TCIC_ADDR, TCIC_IWIN(0, w) + TCIC_IBASE_X);
    base = tcic_getw(TCIC_DATA);
    tcic_setw(TCIC_ADDR, TCIC_IWIN(0, w) + TCIC_ICTL_X);
    ctl = tcic_getw(TCIC_DATA);
    
    printf("  IO window %d: base = %#4.4x, ctl = %#4.4x\n",
	   w, base, ctl);
    printf("    [SOCK=%d]",
	   (ctl & TCIC_ICTL_SS_MASK) >> TCIC_ICTL_SS_SHFT);
    printf(ctl & TCIC_ICTL_ENA ? " [ON]" : " [OFF]");
    if (ctl & TCIC_ICTL_1K) printf(" [1K]");
    if (ctl & TCIC_ICTL_QUIET) printf(" [QUIET]");
    if (ctl & TCIC_ICTL_PASS16) printf(" [PASS16]");
    if (ctl & TCIC_ICTL_ACC) printf(" [ACC]");
    if (ctl & TCIC_ICTL_TINY) printf(" [TINY]");
    switch (ctl & TCIC_ICTL_BW_MASK) {
    case TCIC_ICTL_BW_DYN:
	printf(" [BW_DYN]"); break;
    case TCIC_ICTL_BW_8:
	printf(" [BW_8]"); break;
    case TCIC_ICTL_BW_16:
	printf(" [BW_16]"); break;
    case TCIC_ICTL_BW_ATA:
	printf(" [BW_ATA]"); break;
    }
    printf(" [ws = %d]\n", ctl & TCIC_ICTL_WSCNT_MASK);
}

/*====================================================================*/

void dump_global(void)
{
    dump_syscfg();
    printf("\n");
}

void dump_sock(int s)
{
    dump_sctrl(s);
    dump_sstat(s);
    dump_mode(s);
    dump_pwr(s);
    dump_icsr(s);
    dump_iena(s);
    dump_scf1(s);
    dump_scf2(s);
    dump_wctl(s);
    printf("\n");
}

void dump_windows(void)
{
    int i;
    for (i = 0; i < 8; i++)
	dump_memwin(i);
    for (i = 0; i < 4; i++)
	dump_iowin(i);
}

/*====================================================================*/

int main(int argc, char *argv[])
{
    int sock, i;
    
#ifndef __MSDOS__
    ioperm(tcic_base, 16, 1);
    ioperm(0x80, 1, 1);
#endif
    
    sock = tcic_probe();
    if (sock == 0)
	exit(1);
    dump_global();
    for (i = 0; i < sock; i++) {
	printf("Socket %d:\n", i);
	dump_sock(i);
    }
    dump_windows();
    return 0;
}
