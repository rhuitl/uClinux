/* test4.c */
/*
 Copyright 2001-2005 John Coffman.
 All rights reserved.

 Licensed under the terms contained in the file 'COPYING' in the LILO
 source directory.

*/
#include <bios.h>
#include "../bdata.h"

#define DISK_VERSION "2.4"

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
#define SEQ 0x3C4

#define FS_REG 0x80

#ifndef EDD_SUBSET
#define EDD_SUBSET 4
#define EDD_LOCK 2
#define EDD_PACKET 1
#endif
#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif
#define nelem(a) (sizeof(a)/sizeof((a)[0]))

typedef unsigned char  byte;
typedef unsigned short word;
typedef unsigned long dword;

extern union REGS   __argr;
extern struct SREGS __argseg;

union REGS reg, oreg;
struct SREGS sreg;
int last_good_disk;
int video_1 = 0xF00;
int fs_mod = 0;
int num_hd = BD_MAX_HARD;
int errno;
dword hma;	/* highest memory address */
struct {
  long	start, start_hi,
	length, length_hi,
	mtype;
    } mem_map;
#define E820_MAGIC 0x534D4150

struct gdt_entry {
	unsigned short limit;
	unsigned short base01;
	unsigned char  base2;
	unsigned char  dtype;	/* 0x93 for data */
	unsigned char  limit2;	/* limit in low nibble, granularity & 32-bit in high nibble */
	unsigned char  base3;
};

struct gdt_entry gdt[6];

static
int get_fs(void)
{
#asm
 mov ax,fs
#endasm
}

static
int set_fs(int val)
{
    int i = val;
#asm
 mov ax,4[bp]
 mov fs,ax
#endasm
    return i;
}

static
int check_fs(void)
{
    int ret = 0;

#if DEBUG>=2    
    printf("#");
#endif    
    if (get_fs() != FS_REG) {
        fs_mod = ret = 1;
        printf("\nThe FS register has been modified.\n");
        set_fs(FS_REG);
    }
    return ret;
}

static
int hicopy (unsigned long to, unsigned long from, int wcount)
{
    int status;
    unsigned char save;
    
    memset(gdt, 0, sizeof(gdt));
    gdt[2].limit = gdt[3].limit = 0xFFFF;
    gdt[2].dtype = gdt[3].dtype = 0x93;
    
    gdt[2].base01 = from;
    gdt[2].base2 = from>>16;
    gdt[2].base3 = from>>24;
    
    gdt[3].base01 = to;
    gdt[3].base2 = to>>16;
    save = gdt[3].base3 = to>>24;
    
    segread(&sreg);
    sreg.es = sreg.ds;
    reg.h.ah = 0x87;
    reg.x.cx = wcount;
    reg.x.si = gdt;
/***    gdt[3].base3 &= 0;   / crosstalk */
    int86x(0x15, &reg, &oreg, &sreg);
    
    status = oreg.h.ah;
    if (oreg.x.cflag) status |= 0x100;
    if (save!=gdt[3].base3) status |= 0x200;
    errno |= status;
    return status;
}

unsigned long linear(void *ptr)
{
    segread(&sreg);
    return ((unsigned long)sreg.ds<<4) + (unsigned int)ptr;
}

word hipeekw(long address)
{
    word temp;
    hicopy(linear(&temp), address, 1);
    return temp;
}

int hipokew(long address, word value)
{
    return hicopy(address, linear(&value), 1);
}

#if __MSDOS__==0
static
bios_putc0(int c)
{
    union REGS reg;
    if (c=='\f') {
#if 0
    	reg.h.ah = 0x0F;
    	int86(0x10, &reg, &reg);
    	reg.h.ah = 0;
    	int86(0x10, &reg, &reg);
#else
	static word upper = 0;
	if (!upper) {
	    __set_es(0x40);	/* address BIOS data area */
	    upper = __peek_es(0x84);
	    if (upper < 24 || upper > 50) upper = 24;
	    upper <<= 8;
	    reg.h.ah = 0x0F;	/* get video mode */
	    int86(0x10, &reg, &reg);
	    upper |= (reg.h.ah-1);
	}
	reg.x.ax = 0x0600;	/* blank screen area */
	reg.h.bh = 7;
	reg.x.cx = 0x0000;
	reg.x.dx = upper;
	int86(0x10, &reg, &reg);
	reg.h.ah = 2;		/* set cursor position */
	reg.h.bh = 0;
	reg.x.dx = 0x0000;
	int86(0x10, &reg, &reg);
#endif
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
int a20(void)	/* Return 1 if a20 is enabled, 0 if disabled */
{
#asm
 push	ds
 push	es
 xor	ax,ax
 mov	es,ax
 dec	ax
 mov	ds,ax
 cli
 mov	al,[0x10]
 mov	ah,al
 seg es
 cmp	al,[0]
 jne	a20_8
 xor	al,#0x5A
 mov	[0x10],al
 seg es
 cmp	al,[0]
 jne	a20_8
 xor	al,al
 jmp	a20_9
a20_8:
 mov	al,#1
a20_9:
 mov	[0x10],ah
 cbw
 sti
 pop	es
 pop	ds
#endasm
}

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
">>>> Disk Detection and Parameter Display <<<<\n\n\n"
"Version %s, Copyright (C) 1999-2005  John Coffman <johninsd@san.rr.com>\n"
"Portions Copyright (C) 1996-2001 Robert de Bath, used with permission\n"
"Re-use and redistribution rights set forth in the file \"COPYING\".\n\n",
	 version);
}

static
void testDX(void)
{
#if __MSDOS__==0
   printf("Boot reported from DX = 0x%04x (boot device is 0x%02x in DL)\n", __argr.x.dx, __argr.h.dl);
   if (__argr.h.dl == 0 || __argr.h.dl == 1) {
   	printf("If you booted from the %s floppy drive, then this is correct.",
   		__argr.h.dl ? "second" : "first");
   } else if (__argr.h.dl >= 0x80 && __argr.h.dl <= 0x8f) {
   	printf("If you booted from %s hard drive, then this is correct.",
   		__argr.h.dl==0x80 ? "the first" :
   		__argr.h.dl==0x81 ? "the second" : "a" );
   } else {
	printf("It looks like the BIOS failed to report the boot device in DL.\n");
   }
#endif
}



static
int smsw(void)
{
#asm
  smsw	ax
#endasm
}

static
long e820(long b)
{
#asm
  push	bp
  mov	bp,sp
  push	ds
  pop	es
  mov	di,#_mem_map
  mov	eax,#0xE820
  mov	ebx,[bp+4]
  mov	ecx,#20
  mov	edx,#E820_MAGIC
  stc
  int	0x15
  jc	e820_err
  cmp	eax,#E820_MAGIC
  mov	ax,#-2
  jne	e820_exit
  cmp	ecx,#20
  mov	ax,#-3
  jne	e820_exit
  push	ebx
  pop	ax
  pop	dx
  jmp	e820_exit
e820_err:
  mov	ax,#-1
e820_err2:
  cwd
e820_exit:
  leave
#endasm
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
void v86test(void)
{
static char s1[] = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n";

    if (smsw()&1) {
	printf(s1);
	printf( "!!! ***  Warning:  DOS is not running in REAL mode  *** !!!\n"
		"!!! ***     Reported results may not be accurate    *** !!!\n" );
	printf(s1);
    }
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
        check_fs();
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
   outb(SEQ, 1);
   video_1 = inb(SEQ+1);
/* dirty hack for DELL Dimension 4300 computers */
   printf("\f\n");
}

static void print_carry(int flag)
{
    printf("    Carry = %d\n", flag);
}

static
void get_equip_cfg(void)
{
static char *vmode[4] = { "reserved", "40x25 color",
		"80x25 color", "80x25 monochrome" };
    word flag;
    int n;
    
    pause();
    printf(SPACER
    		"Int 11h\t\t\t\t[PC][AT][PS/2]\n"
    		"Get Equipment Configuration\n\n"
    		"Returns:\n    ");
    flag = int86(0x11, &reg, &reg);
    print_regs(&reg);
    
    printf("\nHas floppy drive(s): "); yesno(flag&1);
    printf("Has math coprocessor: "); yesno(flag&2);
    printf("Has pointing device: "); yesno(flag&4);
    printf("Initial video mode: %s\n", vmode[(flag>>4)&3]);
    n = flag&1 ? ((flag>>6)&3)+1 : 0;
    if (n) printf("Floppy drives installed: %d\n", ((flag>>6)&3)+1 );
    n = (flag>>9)&7;
    printf("Serial interfaces: %d\n", n);
    printf("Has game adapter: "); yesno(flag&4096);
    n = (flag>>14)&3;
    printf("Parallel interfaces: %d\n", n);
}

static
void get_conv_mem(void)
{
    int mem;
    
    pause();
    printf(SPACER
    		"Int 12h\t\t\t\t[PC][AT][PS/2]\n"
    		"Get Conventional Memory Size\n\n"
    		"Returns:\n    ");
    mem = int86(0x12, &reg, &reg);
    print_regs(&reg);
    printf("\nThere is %dK of low memory.    EBDA size = %dK   EBDA starts at 0x%lx\n",
    	mem, 640-mem, (long)mem<<10 );
    printf("\n(The A20 line is %sabled.)\n", a20() ? "en" : "dis");
}

static
void mov_ext_mem(void)
{
    word status, temp, vtemp;
    dword high, veryhigh;
        
    pause();
    segread(&sreg);
    sreg.es = sreg.ds;
    printf(SPACER
    		"Int 15h  Function 87h\t\t[AT][PS/2]\n"
    		"Move Extended Memory Block\n\n"
    		"Call With:\n    ");
    		print_sregs(&sreg);
    		reg.x.ax = 0x8700;
    		reg.x.cx = 1;
    		reg.x.si = &gdt;
    		printf("    ");
    		print_regs(&reg);
    		
    	high = 1024L*(1024L+128)-2;	/* 1Mb + 128K */
    	veryhigh = high+16L*1024L*1024L;
    	if (veryhigh >= hma) veryhigh=0;
#define WORDA 0xA5C6
#define WORDB 0x6CA5

	errno = 0;
	temp = hipeekw(high);
	status = hipokew(high, WORDA^temp);
    	printf("\nReturns:\n    ");
    	print_sregs(&sreg);
    	printf("    ");
    	print_regs(&oreg);
    	print_carry((status>>8) & 1);

	printf("\nR/W test at address %08lx ", high);
	if (hipeekw(high) != (WORDA^temp)) errno |= 0x400;
	hipokew(high, temp);
	if (hipeekw(high) != temp) errno |= 0x800;
	printf("%ssuccessful\n", errno ? "un" : "");
	if (errno) printf("Error code = 0x%04x\n", errno);
	
	if (veryhigh) {
		printf("R/W test at address %08lx ", veryhigh);
		vtemp = hipeekw(veryhigh);
		hipokew(veryhigh, WORDB^vtemp);
		if (hipeekw(high) != temp) errno |= 0x200;
		if (hipeekw(veryhigh) != (WORDB^vtemp)) errno |= 0x400;
		hipokew(veryhigh, vtemp);
		if (hipeekw(high) != temp) errno |= 0x200;
		if (hipeekw(veryhigh) != vtemp) errno |= 0x800;
		printf("%ssuccessful\n", errno ? "un" : "");
		if (errno) printf("Error code = 0x%04x\n", errno);
	}
    	if (errno & 0xE00)
    	    printf("\nThere is crosstalk between the two addresses\n"
    	    	"The function does not support full 386 32-bit addressing.\n");
}

#define NAREA 32

static
void get_ext_mem(void)
{
    long b, b1;
    dword t;
    int i;
    
    pause();
    printf(SPACER
    		"Int 15h  Function E820h\t\t[EXT]\n"
    		"Get Memory Map\n\n"
    		"Call With:\n"
    		"    EAX=0000E820  EBX=00000000  ECX=00000014  EDX=%lx\n\n",
    		E820_MAGIC );

    b = e820(b1=i=0);
    if (b > 0) {
	dword start[NAREA], length[NAREA];
	int j, k, ovlap;

    /*           00    000000000000   000000000000   (1) avail	*/
	printf("EBX        Start         Length      Type\n\n");
	do {
	    printf(" %02lx    %04hx%08lx   %04hx%08lx   (%d) %s\n", b1,
		(short)mem_map.start_hi, mem_map.start,
		(short)mem_map.length_hi, mem_map.length, (int)mem_map.mtype,
		mem_map.mtype == 1 ? "available" :
		mem_map.mtype == 2 ? "reserved"  :
		mem_map.mtype == 3 ? "ACPI" :
		mem_map.mtype == 4 ? "NVS"  :  "unknown-reserved");
	    if (mem_map.mtype==1 && mem_map.start_hi==0 && mem_map.start<=1024L*1024L) {
		if (mem_map.length_hi==0) hma = mem_map.start+mem_map.length;
		else hma = 0xFFF00000L;
	    }
	    if (i < NAREA) {
		start[i] = *(dword*)(((char*)&mem_map.start)+1);
		length[i] = *(dword*)(((char*)&mem_map.length)+1);
	    }
	    i++;
	    b = e820(b1=b);
	} while (b1 > 0);
	printf("\n");
	if (i > NAREA) {
	    i = NAREA;
	}
	ovlap = 0;
	for (k=0; k<i-1; k++) {
	    dword s, e;
	    s = start[k];
	    e = s + length[k];
	    for (j=k+1; j<i; j++) {
	    	dword ss, ee;
	    	ss = start[j];
	    	ee = ss + length[j];
		if (!(ss < s && ee <= s || ss >= e && ee > e)) {
		    printf("*** Memory areas %d and %d overlap ***\n", k, j);
		    ovlap++;
		}
	    }
	}
	if (!ovlap) printf("No memory areas overlap\n");
    } else {
	printf("Returns:\n");
	if (b==-1) print_carry(1);
	else if (b==-2) printf("    EAX=<trash>\n");
	else if (b==-3) printf("    EAX=%lx  EBX=********  ECX=<trash>\n", E820_MAGIC);
	else printf("    EAX=%lx  EBX=00000000\n", E820_MAGIC);
	printf("\nFunction is not supported.\n");
    }


    pause();
    printf(SPACER
    		"Int 15h  Function E801h\t\t[EXT]\n"
    		"Get Extended Memory Blocks\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0xE801;
    print_regs(&reg);
    int86(0x15, &reg, &oreg);
    printf("\nReturns:\n    ");
    print_regs(&oreg);
    print_carry(oreg.x.cflag);

    if (!oreg.x.cflag) {
	printf("\nNumber of 1K blocks between 1M and 16M:  %u\n", oreg.x.ax);
	printf(  "Number of 64K blocks above 16M:  %u\n", oreg.x.bx);
	t = 1024L*(oreg.x.ax+1024);
	t += 64L*1024L*oreg.x.bx;
	if (!hma) hma = t;
	else if (hma!=t) printf("A different amount of memory is reported by this function\n");
    }
    else printf("\nFunction is not supported.\n");

    pause();
    printf(SPACER
    		"Int 15h  Function 88h\t\t[AT][PS/2]\n"
    		"Get Extended Memory Size\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0x8800;
    print_regs(&reg);
    int86(0x15, &reg, &reg);
    printf("\nReturns:\n    ");
    print_regs(&reg);
    printf("\nThere is ");
    decimal( (unsigned long)reg.x.ax );
    printf("K of extended memory.\n");

    t = (reg.x.ax + 1024L) * 1024L;
    if (!hma) hma = t;
}    
    
static
int get_video_mode(void)
{
    int m, row, col;
    
    pause();
    printf(SPACER
    		"Int 10h  Function 0Fh\t\t[MDA][CGA][PCjr]\n"
    		"Get Video Mode\t\t\t[EGA][MCGA][VGA]\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0x0F00;
    reg.x.bx = -1;
    print_regs(&reg);
    int86(0x10, &reg, &reg);
    printf("\nReturns:\n    ");
    print_regs(&reg);
    m = reg.h.al;
    __set_es(0x40);		/* address BIOS data area */
    reg.h.bl = row = __peek_es(0x84);
    printf("Fetch 0040:0084 (rows-1) to BL\n"
    	"--> ");
    print_regs(&reg);
    col = reg.h.ah;
    printf("\nVideo mode = 0x%02x (%dx%d %s)\n", m, col, row+1,
    	m==7 ? "monochrome" : m==3 ? "color" : "unknown");
    printf("Active display page = %d\n", (int)reg.h.bh);
    
    return !(m==7 || col<80);
}

static
int get_cfg_info(void)
{
    pause();
    printf(SPACER
    		"Int 10h  Function 12h\t\t[EGA][VGA]\n"
    		"Subfunction 10h\n"
    		"Get Configuration Information\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0x1200;
    reg.x.bx = 0xFF10;
    print_regs(&reg);
    int86(0x10, &reg, &reg);
    printf("\nReturns:\n    ");
    print_regs(&reg);
    if (reg.h.bh > 1) return 0;
    
    printf("\n%s display\n", reg.h.bh==0 ? "Color" : reg.h.bh==1 ? "Monochrome" : "Unknown");
    printf("EGA memory = %dK\n", reg.h.bl <= 3 ? (reg.h.bl+1)*64 : 0);
    printf("Feature bits = 0x%02x\n", (int)reg.h.ch);
    printf("Configuration switch = 0x%02x\n", (int)reg.h.cl);
    
    return 1;
}

static
int enable_refresh(void)
{
    pause();
    printf(SPACER
    		"Int 10h  Function 12h\t\t[VGA]\n"
    		"Subfunction 36h\n"
    		"Enable Screen Refresh\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0x1200;
    reg.x.bx = 0x0036;
    reg.x.cx = 0;
    reg.x.dx = 0x80;
    print_regs(&reg);
    int86(0x10, &reg, &oreg);
    printf("\nReturns:\n    ");
    print_regs(&oreg);
    
    printf("\n");
    printf("Function is %ssupported.\n", oreg.h.al==0x12 ? "" : "NOT ");
    if (oreg.x.dx != reg.x.dx || oreg.x.cx != reg.x.cx || oreg.x.si != reg.x.si
    		|| oreg.x.di != reg.x.di)
	printf("Error: Register(s) are not preserved.\n");
    reg.x.dx = 0;
    
    return 1;
}

static
int get_comb_code(void)
{
static char *dcode[] = { "none", "Monochrome", "CGA", "reserved",
  "EGA (color)", "EGA (mono)", "PGA", "VGA (monochrome)", "VGA (color)",
  "reserved", "MCGA (digital color)", "MCGA (monochrome)", "MCGA (color)",
  "UNKNOWN" };
    int code;
    
    pause();
    printf(SPACER
    		"Int 10h  Function 1Ah\t\t[PS/2]\n"
    		"Subfunction 00h\n"
    		"Get Display Combination Code\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0x1A00;
    reg.x.bx = reg.x.cx = 0;
    print_regs(&reg);
    int86(0x10, &reg, &reg);
    printf("\nReturns:\n    ");
    print_regs(&reg);
    if (reg.h.al != 0x1A) return 0;
    
    code = reg.h.bl <= 12 ? reg.h.bl : 13;
    printf("\nActive display: %s\n", dcode[code]);
    code = reg.h.bh <= 12 ? reg.h.bh : 13;
    printf("Inactive display: %s\n", dcode[code]);

    return (reg.h.bl>=4);
}

static void print_io_status(int status)
{
static char *errmsg[] = {"no error", "invalid command", 		/* 0-1 */
	"address mark not found", "disk write-protected",	/* 2-3 */
	"sector not found", "reset failed", "floppy disk removed", /* 4-6 */
	"bad parameter table", "DMA overrun",			/* 7-8 */
	"DMA crossed 64k boundary", "bad sector flag",		/* 9-A */
	"bad track flag", "media type not found",		/* B-C */
	"invalid number of sectors on format",			/* D */
	"control data address mark detected",			/* E */
	"DMA arbitration level out of range",			/* F */
	"uncorrectable CRC or ECC data error",			/* 10 */
	"ECC corrected data error"				/* 11 */
			};
    char *err;
			
    if (status <= 0x11) err = errmsg[status];
    else switch(status) {
    	case 0x20: err = "controller failure"; break;
    	case 0x40: err = "seek failed"; break;
    	case 0x80: err = "disk timeout (failed to respond)"; break;
    	case 0xAA: err = "drive not ready"; break;
    	case 0xBB: err = "undefined error"; break;
    	case 0xCC: err = "write fault"; break;
    	case 0xE0: err = "status register error"; break;
    	case 0xFF: err = "sense operation failed"; break;
    	default:   err = "???";
    }
    printf("    BIOS error code = 0x%02x  (%s)\n", status, err);
}

static
void do_edd(int dev)
{
    int m, subset;
    
    pause();
    printf(SPACER
    		"Int 13h  Function 41h\t\t[EDD]\n"
    		"Check EDD Extensions Present (device %02xh)\n\n"
    		"Call With:\n    ", dev);
    reg.x.ax = 0x41ED;
    reg.x.bx = 0x55AA;
    reg.x.dx = dev;
    print_regs(&reg);
    int86(0x13, &reg, &oreg);
    printf("\nReturns:\n    ");
    print_regs(&oreg);
    print_carry(oreg.x.cflag);
    m = 0;
    if (oreg.x.cflag) print_io_status(oreg.h.ah);
    else if (oreg.x.bx == 0xAA55 && (oreg.x.cx&EDD_SUBSET+EDD_LOCK+EDD_PACKET)) {
	m = 1;
	printf("\nEnhanced Disk Drive support: "); yesno(subset=oreg.x.cx&EDD_SUBSET);
	printf("Drive locking and ejecting: "); yesno(oreg.x.cx&EDD_LOCK);
	printf("Device access using packet calls: "); yesno(oreg.x.cx&EDD_PACKET);
	printf("EDD extensions version%s (hex code %02xh)\n",
		oreg.h.ah==0x30 ? " 3.0" : oreg.h.ah==0x21 ? " 1.1" : "" ,oreg.h.ah);
    }
    
    if (m) {
	struct EDDparam {
	    short size;		/* size of this structure */
	    short flags;	/* information flags */
	    long pcyls;		/* number of physical cylinders */
	    long pheads;	/* number of physical heads/cylinder */
	    long psects;	/* number of physical sectors/track */
	    unsigned		/* number of physical sectors on volume */
	    long sectors_lo, sectors_hi;	/* this is 8 bytes long */
	    short sec_size;	/* number of bytes per sector */
	    unsigned
	    long params;	/* EDD config params (valid only if EDD_SUBSET) */
	} eddparam;

	pause();
	m = !!(oreg.x.cx&EDD_SUBSET)  &&  oreg.h.ah>=0x21;
	printf(SPACER
		"Int 13h  Function 48h\t\t[EDD]\n"
		"EDD Get Drive Parameters (device %02xh)\n\n"
		"Call With:\n    ", dev);
	eddparam.size = sizeof(eddparam);
	reg.x.si = &eddparam;	/* DS:SI points to buffer */
	reg.x.ax =0x48C6;
	segread(&sreg);
	print_sregs(&sreg);
	printf("    ");
	print_regs(&reg);
	int86x(0x13, &reg, &reg, &sreg);
	printf("\nReturns:\n    ");
	print_sregs(&sreg);
	printf("    ");
	print_regs(&reg);
	print_carry(reg.x.cflag);
#define fl eddparam.flags	
	printf("\nDMA boundary errors handled transparently: "); yesno(fl&1);
	printf("Geometry supplied: "); yesno(fl&2);
	printf("Device is removable: "); yesno(fl&4);
	printf("Device supports write with verify: "); yesno(fl&8);
	if (fl&4) {
	    printf("Device has change-line support: "); yesno(fl&16);
	    printf("Device is lockable: "); yesno(fl&32);
	    printf("No media present; geometry is set to maximum: "); yesno(fl&64);
	}
	printf("Disk geometry (");
	if (fl&2) {
	    printf("C:H:S) = %ld:%ld:%ld (", eddparam.pcyls, eddparam.pheads,
	    			eddparam.psects);
	}
	if (eddparam.sectors_hi == 0) 
	    decimal(eddparam.sectors_lo);
	else printf("0x%x%08x", eddparam.sectors_hi, eddparam.sectors_lo);
	printf(" sectors)\n");
#undef fl
	m=1;
	if (m) {
	    static char *cfunc[] = {
		"Enable Prefetch",
		"Disable Prefetch",
		"Set Maximum PIO Mode",
		"Set PIO Mode 0",
		"Set Default PIO Mode",
		"Enable DMA Maximum Mode",
		"Disable DMA"
	    };
	    m = 0;		/* start with subfn 0 */
	    pause();
	    printf(SPACER
		"Int 13h  Function 4Eh\t\t[EDD]\n"
		"Subfunction 0?h\n"
		"EDD Set Hardware Configuration (device %02xh)\n\n"
		"Call With:\n    ", dev);
	    reg.x.ax = 0x4E00;
	    reg.h.dl = dev;
	    print_regs(&reg);
	    int86(0x13, &reg, &reg);
	    printf("\nReturns:\n    ");
	    print_regs(&reg);
	    print_carry(reg.x.cflag);
	    printf("\n");
	    
	    for (m=0; m<nelem(cfunc); m++) {
		reg.x.ax = 0x4E00 + m;
		reg.h.dl = dev;
		int86(0x13, &reg, &reg);
		printf("Subfn(%d):  %s  <--  ", m, cfunc[m]);
		if (reg.x.cflag || reg.h.ah) {
		    printf("is not supported.\n");
		}
		else {
		    printf("%s other drives on controller.\n",
			reg.h.al ? "affects" : "does not affect");
		}
	    } /* for */
	    
	} /* if (m) */
	
    } /* if (m) */
}

static
int do_disk(int dev)
{
static char *drvtyp[] = {"No drive present", "Floppy w/o change-line support",
	"Floppy with change-line support"};
static char *dt[] = {	"5.25\", 40 track, 360K",
			"5.25\", 80 track, 1.2M",
			"3.5\", 80 track, 720K",
			"3.5\", 80 track, 1.44M" };
    int m, mm;
    int c,h,s;
    unsigned long sect;
    
    pause();
    printf(SPACER
    		"Int 13h  Function 15h\t\t[AT][PS/2]\n"
    		"Get Disk Type  (device %02xh)\n\n"
    		"Call With:\n    ", dev);
    reg.x.ax = 0x1500;
    reg.x.bx = 0;
    reg.x.dx = dev;
    print_regs(&reg);
    int86(0x13, &reg, &oreg);
    printf("\nReturns:\n    ");
    print_regs(&oreg);
    print_carry(oreg.x.cflag);
    mm = (oreg.x.cflag==0 && oreg.h.ah!=0);
    m = mm || (dev&0x80)==0;
    if (oreg.x.cflag) print_io_status((int)oreg.h.ah);
    else {
	printf("\n%s",
	    oreg.h.ah < 3 ? drvtyp[oreg.h.ah] :
	    oreg.h.ah != 3 ? "unknown drive type" : "");
	if (oreg.h.ah == 3) {
	    printf("Fixed disk with ");
	    sect = (long)oreg.x.cx<<16 | oreg.x.dx;
	    decimal(sect);
	    printf(" sectors = ");
	    sizeit(sect);
	}
	printf("\n");
    }

    if (m) {
	pause();
	printf(SPACER
			"Int 13h  Function 08h\t\t[PC][AT][PS/2]\n"
			"Get Drive Parameters  (device %02xh)\n\n"
			"Call With:\n    ", dev);
	reg.x.ax = 0x0800;
	reg.x.dx = dev;
	reg.x.di = 0x4321;
	reg.x.bx = 0x1234;
	segread(&sreg);
	sreg.es = 0;
	print_sregs(&sreg);
	printf("    ");
	print_regs(&reg);
	int86x(0x13, &reg, &oreg, &sreg);
	printf("\nReturns:\n    ");
	print_sregs(&sreg);
	printf("    ");
	print_regs(&oreg);
	print_carry(oreg.x.cflag);
	if (oreg.x.cflag) print_io_status((int)oreg.h.ah);
	else {
	    last_good_disk = dev;
	    if (mm) {
		printf("\n");
		if (!(dev&0x80)) {
		    printf("Disk type %d = %s\n", (int)oreg.h.bl,
					dt[(oreg.h.bl-1)&3] );
		    printf("Parameter table at %04x:%04x\n",
					sreg.es, oreg.x.di);
		}
		else {
		    if (oreg.x.bx != reg.x.bx)
			printf("Error:  Hard disk BIOS should not touch BX\n");
		    if (sreg.es != 0  ||  oreg.x.di != reg.x.di)
			printf("Error:  Hard disk BIOS should not touch ES:DI\n");
		}
		s = (oreg.h.cl & 0x3F);		/* sectors 1..63 */
		if (s == 0) s = 64;
		h = (int)oreg.h.dh + 1;		/* heads 0..254 */
		c = (((oreg.h.cl & 0xC0)<<2) | oreg.h.ch) + 1;
		printf("Disk geometry (C:H:S) = %d:%d:%d (", c, h, s);
		decimal( sect=(long)c*h*s );
		printf(" sectors) = ");
		sizeit(sect);
		printf("\n%s disks on system = %d\n",
			dev&0x80 ? "Fixed" : "Floppy", oreg.h.dl);
                if (s > 63)  printf("BIOS BUG!!!  sectors returned as zero; 64 assumed\n");
                if (h > 255) printf("BIOS BUG!!!  heads > 255; BIOS is not IBM compatible\n");
		if (dev & 0x80) {
		    if (dev == 0x80) num_hd = oreg.h.dl;
		    do_edd(dev);
		}
	    }
	}
    }
    
    return m;
}

static
int do_rw(int tries)
{
    int code;
    
    while (tries--) {
	int86x(0x13, &reg, &oreg, &sreg);
	if (oreg.x.cflag == 0 && oreg.x.ax == 0x0001) return 0;
	code = oreg.h.ah;
	oreg.x.ax = 0;
	int86(0x13, &oreg, &oreg);
    }
    return code;
}

static
void do_get_pt(int dev)
{
    int m;
    char buf[SECTOR_SIZE];
    
    printf("Get partition table (device = 0x%x): ", dev);
    segread(&sreg);
    sreg.es = sreg.ss;
    reg.x.ax = 0x0201;
    reg.x.bx = buf;
    reg.x.cx = 1;
    reg.x.dx = dev & 0xFF;
    m = do_rw(5);
    if (m) print_io_status(m);
    else printf("  okay");
    printf("\n");
    check_fs();
}

static
void do_vesa(void)
{
    int i;
    char vesa[512];
    
    pause();
    printf(SPACER
    		"Int 10h  Function 4Fh\t\t[VESA]\n"
    		"Subfunction 00h\n"
    		"Check VESA Extensions Present\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0x4F00;
    reg.x.bx = 0;
    segread(&sreg);
    sreg.es = sreg.ss;
    reg.x.di = &vesa[0];
    print_sregs(&sreg);
    printf("    ");
    print_regs(&reg);
    int86x(0x10, &reg, &oreg, &sreg);
    printf("\nReturns:\n    ");
    print_sregs(&sreg);
    printf("    ");
    print_regs(&oreg);
    if (oreg.x.ax != 0x004F) {
	printf("\nVESA BIOS extensions not present\n");
	return;
    }
    if (strncmp(vesa, "VESA", 4)) {
	printf("\nVESA signature not found\n");
	return;
    }
    vesa[4] = 0;
    printf("\n\"%s\" BIOS extensions present\n", vesa);

    pause();
    printf(SPACER
    		"Int 10h  Function 4Fh\t\t[VESA]\n"
    		"Subfunction 01h\n"
    		"Get VESA Mode Information 1\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0x4F01;
    reg.x.cx = 0x101;
    segread(&sreg);
    sreg.es = sreg.ss;
    reg.x.di = &vesa[0];
    print_sregs(&sreg);
    printf("    ");
    print_regs(&reg);
    int86x(0x10, &reg, &oreg, &sreg);
    printf("\nReturns:\n    ");
    print_sregs(&sreg);
    printf("    ");
    print_regs(&oreg);
    i = *(int*)vesa;	/* get mode bits */
    printf("\nMode bits:  0x%04x\n", i);
    printf("640x480x256 mode supported: ");
    yesno(!(0x19 & ~i));
    
    pause();
    printf(SPACER
    		"Int 10h  Function 4Fh\t\t[VESA]\n"
    		"Subfunction 01h\n"
    		"Get VESA Mode Information 3\n\n"
    		"Call With:\n    ");
    reg.x.ax = 0x4F01;
    reg.x.cx = 0x103;
    segread(&sreg);
    sreg.es = sreg.ss;
    reg.x.di = &vesa[0];
    print_sregs(&sreg);
    printf("    ");
    print_regs(&reg);
    int86x(0x10, &reg, &oreg, &sreg);
    printf("\nReturns:\n    ");
    print_sregs(&sreg);
    printf("    ");
    print_regs(&oreg);
    i = *(int*)vesa;	/* get mode bits */
    printf("\nMode bits:  0x%04x\n", i);
    printf("800x600x256 mode supported: ");
    yesno(!(0x19 & ~i));
}

void main(void)
{
    int m, i, dev;
    
    set_fs(FS_REG);
#if DEBUG>=1
    printf("FS=%04x\n", get_fs());
    pause();
#endif
    
    if (!is_msdos()) {
/**	atexit(pause);	**/
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
    check_fs();
    print_sregs(&sreg);
#endif
    check_fs();
    banner(DISK_VERSION);
    check_fs();
    v86test();
    testDX();
#if DEBUG>=2
    sizeit((long)40*2*9);  putch('\n');
    sizeit((long)80*2*15);  putch('\n');
    sizeit((long)80*2*18);  putch('\n');
    sizeit((long)80*2*36);  putch('\n');
    sizeit((long)1024*255*63);  putch('\n');
    sizeit((long)24000*512);  putch('\n');
#endif
    get_equip_cfg();
    get_conv_mem();
    hma = 0;
    get_ext_mem();
    if (hma>1024L*1024L) mov_ext_mem();
    m = get_video_mode();
    if (m) m = get_cfg_info();
    if (m) m = enable_refresh();
    if (m) m = get_comb_code();
    if (m) do_vesa();
#if DEBUG>=3
    printf("\n\nm=%x\n", m);
#endif
    dev = 0; m = 1;
    for (i=BD_MAX_FLOPPY; i && m;) {
	m = do_disk(dev);
	++dev;
	if (--i == 0  &&  (dev & 0x80)==0) {
	    dev = 0x80;
	    i = BD_MAX_HARD;
	}
	if ((dev & 0x7F) >= num_hd) m = 0;
    }
    pause();
    printf(SPACER);
    for (dev = 0x80; dev <= last_good_disk; dev++) do_get_pt(dev);
    
    if (!is_msdos()) {
	printf("\n\nInitial SEQ reg 1:  0x%02x\n", video_1);
    }
    printf("The FS register was %smodified during the tests.\n",
	    fs_mod ? "" : "NOT ");
    pause();
}
