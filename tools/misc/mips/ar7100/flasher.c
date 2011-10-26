/*****************************************************************************/

/*
 *	flasher - simple code to flash program the SPI flash on
 *		  Atheros 7100 based board.
 *
 *	(C) Copyright 2008, Greg Ungerer <gerg@snapgear.com>
 */

/*****************************************************************************/

#include "mips.h"

#define	FLASH_SECTORSIZE	(64 * 1024)
#define	FLASH_PAGESIZE		256

/*
 *	If you want to use serial image loading, then define this.
 *	It is much quicker, loading boot loaders through the JTAG
 *	interface is very slow.
 */
#define	SERIALLOAD	1

/*****************************************************************************/

static inline void writel(unsigned int addr, unsigned int v)
{
	*((volatile unsigned int *) addr) = v;
}

static inline unsigned int readl(unsigned int addr)
{
	return *((volatile unsigned int *) addr);
}

static inline void writeb(unsigned int addr, unsigned char v)
{
	*((volatile unsigned char *) addr) = v;
}

static inline unsigned int readb(unsigned int addr)
{
	return *((volatile unsigned char *) addr);
}

/*****************************************************************************/

void putch(unsigned char c)
{
	while ((readb(0x18020017) & 0x40) == 0)
		;
	writeb(0x18020003, c);
}

void putstr(char *s)
{
	while (*s != '\0')
		putch(*s++);
}

void putnum(unsigned int val)
{
        static char     hexdigits[] = "0123456789abcdef";
        int             i, s;

        for (i = 0, s = 8-1; (i < 8); i++, s--)
                putch(hexdigits[(val >> (s*4)) & 0xf]);
}

int checkch(void)
{
	return (readb(0x18020017) & 0x1);
}

char getch(void)
{
	return readb(0x18020003);
}

/*****************************************************************************/

void spi_flash_send_byte(unsigned char v)
{
	unsigned char bit;
	int i;
	for (i = 7; (i >= 0); i--) {
		bit = (v >> i) & 0x1;
		writel(0x1f000008, 0x60000 | bit);
		writel(0x1f000008, 0x60100 | bit);
	}
}

void spi_flash_send_addr(unsigned int addr)
{
	spi_flash_send_byte((addr >> 16) & 0xff);
	spi_flash_send_byte((addr >> 8) & 0xff);
	spi_flash_send_byte(addr & 0xff);
}

void spi_flash_write_enable(void)
{
	writel(0x1f000000, 1);
	writel(0x1f000008, 0x70000);
	writel(0x1f000008, 0x60000);
	spi_flash_send_byte(6);
	writel(0x1f000008, 0x70000);
	writel(0x1f000000, 0);
}

void spi_flash_wait(void)
{
	unsigned int v;

	writel(0x1f000000, 1);
	writel(0x1f000008, 0x70000);
	writel(0x1f000008, 0x60000);
	spi_flash_send_byte(5);

	do {
		spi_flash_send_byte(0);
		v = readl(0x1f00000c);
	} while (v & 0x1);

	writel(0x1f000008, 0x70000);
	writel(0x1f000000, 0);
}

void spi_flash_erase(unsigned int addr)
{
	spi_flash_write_enable();

	writel(0x1f000000, 1);
	writel(0x1f000008, 0x70000);
	writel(0x1f000008, 0x60000);
	spi_flash_send_byte(0xd8);
	spi_flash_send_addr(addr);
	writel(0x1f000008, 0x70000);
	writel(0x1f000000, 0);

	spi_flash_wait();
}

void spi_flash_write_page(void *from, unsigned int addr)
{
	unsigned char *p = from;
	int i;

	spi_flash_write_enable();

	writel(0x1f000000, 1);
	writel(0x1f000008, 0x70000);
	writel(0x1f000008, 0x60000);
	spi_flash_send_byte(2);
	spi_flash_send_addr(addr);

	for (i = 0; (i < FLASH_PAGESIZE); i++)
		spi_flash_send_byte(*p++);

	writel(0x1f000008, 0x70000);
	writel(0x1f000000, 0);

	spi_flash_wait();
}

void spi_flash_program(void *from, unsigned int addr, unsigned int len)
{
	unsigned int i, j;

	j = addr + len;
	putstr("Erasing: ");
	for (i = addr; (i < j); i += FLASH_SECTORSIZE) {
		spi_flash_erase(i);
		putch('.');
	}
	putch('\n');

	putstr("Programming: ");
	for (i = addr; (i < j); i += FLASH_PAGESIZE) {
		spi_flash_write_page(from, i);
		from += FLASH_PAGESIZE;
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

int main()
{
	int len;
	putstr("SPI flash programmer\n");

#ifdef SERIALLOAD
	len = serial_load((void *) 0x00100000);
	spi_flash_program((void *) 0x00100000, 0, len);
#else
	spi_flash_program((void *) 0x00100000, 0, len);
#endif

	putstr("Done\n");
	return 0;
}

/*****************************************************************************/
