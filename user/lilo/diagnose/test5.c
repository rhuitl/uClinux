/* test5.c */
/*
 Copyright (C) 2004 John Coffman.
 All rights reserved.

 Licensed under the terms contained in the file 'COPYING' in the LILO
 source directory.

*/
#include <bios.h>
#include <time.h>
#include "../bdata.h"

#define DISK_VERSION "3.0"

#if __MSDOS__==0
#define putch bios_putc
#define getch bios_getc
#define printf cprintf
#define CR 13
#else
#include <stdio.h>
#define putch(c) fputc((c),stdout)
#define getch getchar
#define CR 10
#endif

#define CTRL_C 03
#define SPACER "\f\n"


#ifndef EDD_SUBSET
#define EDD_SUBSET 4
#define EDD_LOCK 2
#define EDD_PACKET 1
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif

#define CL_MAGIC_ADDR 0x20
#define CL_MAGIC 0xa33f
#define CL_OFFSET 0x22
#define CL_LENGTH 256

typedef unsigned char  byte;
typedef unsigned short word;
typedef unsigned long dword;

extern union REGS   __argr;
extern struct SREGS __argseg;

union REGS reg, oreg;
struct SREGS sreg;

int num_hd = BD_MAX_HARD;
int errno;
enum {RD=0, WR=1};

struct Buffer {
    int dirty, device;
    union {
	byte sector[SECTOR_SIZE];
	word wsector[SECTOR_SIZE/2];
	dword dsector[SECTOR_SIZE/4];
    } x;
} buffer;

unsigned long linear(void *ptr)
{
    segread(&sreg);
    return ((unsigned long)sreg.ds<<4) + (unsigned int)ptr;
}


#if __MSDOS__==0
static
bios_putc0(int c)
{
    union REGS reg;
    if (c=='\f') {
    	reg.h.ah = 0x0F;
    	int86(0x10, &reg, &reg);
    	reg.h.ah = 0;
    	int86(0x10, &reg, &reg);
    } else {
    	reg.h.al = c;
    	reg.h.ah = 14;
    	reg.x.bx = 7;
    	int86(0x10, &reg, &reg);
    }
}

void bios_putc(char c)
{
static int col;
   
    switch(c) {
    case '\t':
	do bios_putc(' '); while(col&7);
	break;
    case '\n':  bios_putc0('\r');
	/* fall into CR */
    case '\f':
    case '\r':	col=0;
    default:
        bios_putc0(c);
    	if (c>=' ' && c<0177) col++;
    }
}
#endif

static
void sizeit(unsigned long sectors)
{
static char suf[] = "KMGT";
    int fract;
    char *cp;

/* print disk size in K,M,G,T */
    sectors /= 2;
    cp = suf;
    if (sectors <= 999) {
	printf("%ld%c", sectors, *cp);
	return;
    }
    cp++;
    while (sectors > 999999) {
	sectors /= 1000;
	cp++;
    }
    if (sectors > 2999) {
	sectors *= 1024;
	sectors /= 1000;
    }
    sectors += 5;	/* round decimal part */
    sectors /= 10;
    fract = sectors % 100;
    sectors /= 100;
    printf("%ld.%02d%c", sectors, fract, *cp);
}

static
void banner(char *version)
{
	printf(	"\n\n\n"
">>>> Disk Maintenance Tools <<<<\n\n\n"
"Version %s, Copyright (C) 2004  John Coffman <johninsd@san.rr.com>\n"
"Portions Copyright (C) 1996-2001 Robert de Bath, used with permission\n"
"Re-use and redistribution rights set forth in the file \"COPYING\".\n\n",
	 version);
}



static
int inb(int port)
{
#asm
  mov	bx,sp
  mov	dx,[bx+2]
  in	al,dx
  xor	ah,ah
#endasm
}

static
int outb(int port, int data)
{
#asm
  mov	bx,sp
  mov	dx,[bx+2]
  mov	ax,[bx+4]
  out	dx,al
#endasm
}

static
void yesno(int i)
{
    printf("%s\n", i?"yes":"no");
}

static
void decimal(unsigned long value)
{
    unsigned int v[4];
    int i;
    for (i=0; i<4; i++) {
    	v[i] = value % 1000;
    	value /= 1000;
    }
    if (v[3]) printf("%d,%03d,%03d,%03d", v[3], v[2], v[1], v[0]);
    else if (v[2]) printf("%d,%03d,%03d", v[2], v[1], v[0]);
    else if (v[1]) printf("%d,%03d", v[1], v[0]);
    else printf("%d", v[0]);
}

static
void print_regs(union REGS *reg) {
    printf("AX=%04x  BX=%04x  CX=%04x  DX=%04x  SI=%04x  DI=%04x\n",
    reg->x.ax, reg->x.bx, reg->x.cx, reg->x.dx, reg->x.si, reg->x.di);
}

static 
void print_sregs(struct SREGS *sreg) {
    printf("DS=%04x  ES=%04x  CS=%04x  SS=%04x\n",
    		sreg->ds, sreg->es, sreg->cs, sreg->ss);
}

static
int is_msdos(void)
{
#if __MSDOS__
    return 1;
#else
    return (__argseg.es+0x10 == __argseg.cs);
#endif
}

static
void pause(void)
{
	char ch;
/* Must be standalone */    
	printf("\n\n\nHit <Enter> to continue, <^C> to quit ...");
	do {
	    ch = getch();
	    if (ch==CTRL_C) exit(0);
#if DEBUG>=1
	    if (ch != CR) printf(" %o", ch);
#endif
	} while (ch != CR);
	printf("\n");
}

static
void video_fix(void)
{
/* dirty hack for DELL Dimension 4300 computers */
   printf("\f\n");
}


static
void setup(int rval)
{
    segread(&sreg);
    sreg.es = sreg.ds;		/* as a general rule */
    memset(&reg,rval,sizeof(reg));
    memset(&oreg,rval,sizeof(oreg));
}




static
int peekw_es(int addr)
{
    union {
	char ch[2];
	int  w;
	} tem;
    tem.ch[0] = __peek_es(addr);
    tem.ch[1] = __peek_es(addr+1);
    return tem.w;
}


static void get_cmdline(char *cp)
{
    word addr;
    int ch;
    
    __set_es(__argseg.ds);
    if (peekw_es(CL_MAGIC_ADDR) == CL_MAGIC) {
	addr = peekw_es(CL_OFFSET);
	do {
	    ch = __peek_es(addr++);
	} while (ch && ch != '=');
	do {
	    *cp++ = ch = __peek_es(addr++);
	} while (ch);
    }
    else *cp = 0;
}

static
int num_hard_disks(void)
{
    setup(0);
    reg.h.ah = 8;
    reg.h.dl = 0x80;
    int86(0x13, &reg, &oreg);
    return oreg.x.cflag ? 0 : (int)oreg.h.dl;
}

static
int disk_rw0(int bios, int rw, void *buffer)
{
    int err = 1;
    int errcnt = 5;
    int code;
    while (err && errcnt) {
	setup(0);
	reg.h.ah = 2 + (rw & !DEBUG);
	reg.h.al = 1;
	reg.x.cx = 1;	/* sector=0  is  sect=1, hd=0, cyl=0 */
	reg.h.dh = 0;
	reg.h.dl = bios;
	reg.x.bx = (word)buffer;
	/* ES is set == DS */
	int86x(0x13, &reg, &oreg, &sreg);
	code = oreg.h.ah;
	if ((err = (oreg.x.cflag || oreg.h.ah))) {
	    setup(0);
	    reg.h.dl = bios;
	    if (bios & 0x80) reg.h.ah = 0x0D;
	    int86(0x13, &reg, &oreg);
	    --errcnt;
	}
    } /* while (err && errcnt) */
    if (err) {
	printf("Disk error on 0x%02x, AH = 0x%02x\n", bios, code);
	exit(1);
    }
    return code;
}

void disk_data(int bios)
{
    if (!disk_rw0(bios, RD, buffer.x.sector)) {
	printf("   %02x   %08lx\n", bios, buffer.x.dsector[110]);
    }
}

void main(void)
{
    int m, i, dev;
    char cp[CL_LENGTH];
    
    if (!is_msdos()) {
	video_fix();	/* for Dumb DELL computers */
    }
#if DEBUG>=1 && __MSDOS__==0
    printf("Beginning of '___cstartup'\n");
    print_regs(&__argr);
    printf("DS=%04x  ES=%04x  CS=%04x  SS=%04x  SP=%04x  BP=%04x\n",
    	__argseg.ds, __argseg.es, __argseg.cs, __argseg.ss,
    	__argr.x.flags, __argr.x.cflag);
        
    segread(&sreg);
    printf("\nBeginning of '_main'\n");
    print_sregs(&sreg);
#endif
    banner(DISK_VERSION);
    get_cmdline(cp);
    printf("Command line: '%s'   time=%ld\n", cp, time(NULL));   
    num_hd = num_hard_disks();
    printf("The BIOS reports %d hard disks.\n", num_hd);
    for (i=0; i<num_hd; i++) disk_data(0x80+i);
    
    if (!is_msdos()) {
	pause();
    }
}
