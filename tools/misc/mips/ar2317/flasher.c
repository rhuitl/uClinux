/*****************************************************************************/

/*
 *	flasher - simple code to flash program the SPI flash on
 *		  Atheros 2317 based board.
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
	while ((readb(0x11100017) & 0x40) == 0)
		;
	writeb(0x11100003, c);
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
	return (readb(0x11100017) & 0x1);
}

char getch(void)
{
	return readb(0x11100003);
}

/*****************************************************************************/

unsigned int spi_sendcmd(unsigned int cmd, unsigned int data, int tx, int rx)
{
	unsigned int s;

	/* Wait for SPI interface to be not busy */
	do {
		s = readl(0x11300000);
	} while (s & 0x00010000);

	writel(0x11300008, data);
	writel(0x11300004, cmd);

	s = 0x03000100 | tx | (rx << 4);
	writel(0x11300000, s);

	/* Wait for SPI interface to be done */
	do {
		s = readl(0x11300000);
	} while (s & 0x00010000);

	/* Get result, and mask as necessary */
	s = readl(0x11300008);
	switch (rx) {
	case 1:	s &= 0xff; break;
	case 2:	s &= 0xffff; break;
	case 3:	s &= 0xffffff; break;
	case 4:	s &= 0xffffffff; break;
	default: s = 0 ; break;
	}

	return s;
}

void spi_flash_erase(unsigned int addr)
{
	unsigned int cmd, s;

	/* Send WRITE ENABLE command */
	spi_sendcmd(0x6, 0, 1, 0);

	/* Send ERASE command (with address) */
	cmd = (addr << 8) | 0xd8;
	spi_sendcmd(cmd, 0, 4, 0);

	/* Wait for it to complete */
	do {
		s = spi_sendcmd(0x5, 0, 1, 1);
	} while (s & 0x1);
}

void spi_flash_write_page(void *from, unsigned int addr)
{
	unsigned int cmd, end, s, v;
	unsigned char *ap;

	ap = from;
	end = addr + FLASH_PAGESIZE;
	for (; (addr < end); addr += 4, ap += 4) {
		/* Send WRITE ENABLE command */
		spi_sendcmd(0x6, 0, 1, 0);

		/* Send the WRITE command and data */
		v = (ap[3] << 24) | (ap[2] << 16) | (ap[1] << 8) | ap[0];
		cmd = (addr << 8) | 0x2;
		spi_sendcmd(cmd, v, 8, 0);

		/* Wait for it to complete */
		do {
			s = spi_sendcmd(0x5, 0, 1, 1);
		} while (s & 0x1);
	}
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
		for (idle = 0; (idle < 200000); idle++) {
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
