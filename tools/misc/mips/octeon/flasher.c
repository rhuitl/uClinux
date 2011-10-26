/*****************************************************************************/

/*
 *	flasher - simple code to program the flash on the OCTEON
 *		  based boards.
 *
 *	(C) Copyright 2008-2009, Greg Ungerer <gerg@snapgear.com>
 */

/*****************************************************************************/

#include "mips.h"

/*****************************************************************************/

#ifdef CONFIG_SG590
#define	CPUCLOCK	700000000
#endif
#ifdef CONFIG_SG8100
#define	CPUCLOCK	500000000
#endif
#ifdef CONFIG_SG770
#define	CPUCLOCK	700000000
#endif

/*****************************************************************************/

/*
 * Define the core clock frequency of the CPU.
 */
#ifndef CPUCLOCK
#define	CPUCLOCK	500000000
#endif

/*
 * Define the size of the region we will program.
 */
#ifndef BOOTSIZE
#define	BOOTSIZE	(128 * 1024)
#endif

/*****************************************************************************/

static inline void writel(unsigned long addr, unsigned long v)
{
	*((volatile unsigned long *) addr) = v;
}

static inline unsigned long readl(unsigned long addr)
{
	return *((volatile unsigned long *) addr);
}

static inline void writeb(unsigned long addr, unsigned char v)
{
	*((volatile unsigned char *) addr) = v;
}

static inline unsigned long readb(unsigned long addr)
{
	return *((volatile unsigned char *) addr);
}

/*****************************************************************************/

static void delay(unsigned long cnt)
{
	for (; (cnt); cnt--)
		*((volatile unsigned long *) 0);
}

/*****************************************************************************/
#if defined(CONFIG_SG770)
/*****************************************************************************/

void initled(void)
{
	writel(0x8001180000000018, 0x8fff1f80);
	writeb(0x1f800000, 0xff);
}

unsigned char ledchase[] = {
	0xff, 0xfe, 0xfb, 0xef, 0xbf, 0xdf, 0xf7, 0xfd,
};

void cycleled(void)
{
	int i;

	for (i = 0; ;) {
		delay(50000000);
		writeb(0x1f800000, ledchase[i]);
		if (++i >= sizeof(ledchase))
			i = 0;
	}
}

/*****************************************************************************/
#else
/*****************************************************************************/

void initled(void)
{
	writel(0x8001070000000810, 0x1);
	writel(0x8001070000000818, 0x1);
	writel(0x8001070000000820, 0x1);
	writel(0x8001070000000828, 0x1);
	writel(0x8001070000000830, 0x1);
	writel(0x8001070000000838, 0x1);
	writel(0x8001070000000840, 0x1);
	writel(0x8001070000000888, 0x1fc);
}

unsigned long ledchase[] = {
	0x004, 0x008, 0x010, 0x020, 0x040, 0x080,
	0x100, 0x080, 0x040, 0x020, 0x010, 0x008,
};

void cycleled(void)
{
	int i;

	for (i = 0; ;) {
		delay(15000000);
		writel(0x8001070000000888, ledchase[i]);
		if (i++ >= 11)
			i = 0;
		writel(0x8001070000000890, ledchase[i]);
	}
}
/*****************************************************************************/
#endif /* !CONFIG_SG770 */
/*****************************************************************************/

#define	UARTCLOCK		(CPUCLOCK / 16)
#define	UARTDIVISOR		(UARTCLOCK / 115200)

void initserial(void)
{
	writel(0x8001180000000818, 0x83);
	writel(0x8001180000000880, (UARTDIVISOR & 0xff));
	writel(0x8001180000000888, ((UARTDIVISOR >> 8) & 0xff));
	writel(0x8001180000000818, 0x03);
}

void putch(char c)
{
	while ((readl(0x8001180000000828) & 0x40) == 0)
		;
	writel(0x8001180000000840, c);
}

void putstr(char *s)
{
	while (*s != '\0')
		putch(*s++);
}

char hexdigits[] = "0123456789abcdef";

void putnum64(unsigned long val)
{
	int i, s;

	for (i = 0, s = 16-1; (i < 16); i++, s--)
		putch(hexdigits[(val >> (s*4)) & 0xf]);
}

void putnum32(unsigned int val)
{
	int i, s;

	for (i = 0, s = 8-1; (i < 8); i++, s--)
		putch(hexdigits[(val >> (s*4)) & 0xf]);
}

void putnum8(unsigned char val)
{
	putch(hexdigits[(val >> 4) & 0xf]);
	putch(hexdigits[val & 0xf]);
}

void hexdump(unsigned long addr, unsigned int len)
{
	int i;
	for (i = 0; (i < len); i++) {
		if ((i % 16) == 0) { putnum64(addr + i); putstr(":  "); }
		putnum8(readb(addr + i));
		putch(' ');
		if (((i+1) % 16) == 0) putstr("\n");
	}
}

#if 0
int checkch(void)
{
	return (readb(0x18020017) & 0x1);
}

char getch(void)
{
	return readb(0x18020003);
}
#endif

/*****************************************************************************/

#define	FLASH_SECTORSIZE	(128*1024)


void flash_unlock(unsigned long addr)
{
	writeb(addr, 0x60);
	writeb(addr, 0xd0);

	while ((readb(addr) & 0x80) == 0)
		;

	writeb(addr, 0xff);
}

void flash_erase(unsigned long addr)
{
	writeb(addr, 0x20);
	writeb(addr, 0xd0);

	while ((readb(addr) & 0x80) == 0)
		;

	writeb(addr, 0xff);
}

void flash_writebyte(unsigned long addr, unsigned char v)
{
	writeb(addr, 0x40);
	writeb(addr, v);

	while ((readb(addr) & 0x80) == 0)
		;

	writeb(addr, 0xff);
}

void flash_writeblock(unsigned long addr, unsigned char *buf, int len)
{
	for (; (len); len--)
		flash_writebyte(addr++, *buf++);
}

void flash_program(void *from, unsigned int len)
{
	unsigned long addr = 0x1fc00000;
	unsigned long i, j;

	j = addr + len;
	putstr("Erasing: ");
	for (i = addr; (i < j); i += FLASH_SECTORSIZE) {
		flash_unlock(i);
		flash_erase(i);
		putch('.');
	}
	putch('\n');

	putstr("Programming: ");
	for (i = addr; (i < j); i += FLASH_SECTORSIZE) {
		flash_writeblock(i, from, FLASH_SECTORSIZE);
		from += FLASH_SECTORSIZE;
		putch('.');
	}
	putch('\n');
}

/*****************************************************************************/

#ifdef SERIALLOAD

unsigned int serial_load(void *dst)
{
	unsigned char *p = dst;
	unsigned int idle, len;

	putstr("Send binary now...");

	len = 0;
	while (len == 0) {
		for (idle = 0; (idle < 2000000); idle++) {
			if (checkch()) {
				*p++ = getch();
				len++;
				idle = 0;
			}
		}
	}

	putstr("\nReceived 0x");
	putnum(len);
	putstr(" bytes\n");

	return len;
}

#endif /* SERIALLOAD */

/*****************************************************************************/

int main(void)
{
	int len;

	initserial();
	putstr("\nSnapGear/OCTEON (CN5xxx) flash programmer\n");

#ifdef SERIALLOAD
	len = serial_load((void *) 0x100000);
	flash_program((void *) 0x100000, len);
#else
	flash_program((void *) 0x100000, BOOTSIZE);
#endif

	putstr("Done\n");

	initled();
	cycleled();
	return 0;
}

/*****************************************************************************/
