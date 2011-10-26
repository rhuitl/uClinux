#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <asm/mcfmbus.h>

#define	MBUSDEVICE	"/dev/mbus"

static const unsigned char init[] =
{
	0x06, 0x09,
	0x0b, 0x03,
	0x54, 0x01,
	0x55, 0x35,
	0x52, 0x04,
	0x51, 0x00,	
	0x64, 0x55,
	0x65, 0x55,
	0x50, 0x10,
	0x61, 0x0f,
	0x05, 0xa1,
	0x0d, 0x04,
	0x18, 0x04,
	0x63, 0x00,
	0x0c, 0x01,

};

static int write_block(unsigned char slave, unsigned const char *data, unsigned int len)
{
	int ack = 0;
	unsigned char buf[128];
	unsigned char subaddr;
	int ofd, n, i,count; 

	if ((ofd = open(MBUSDEVICE, O_RDWR)) < 1) {
		printf("ERROR: failed to open MBUS device %s\n", MBUSDEVICE);
		exit(1);
	}
	ioctl(ofd,MBUSIOCSSLADDR,slave);

	while (len > 1) 
		{
		while (len > 1 && *data == ++subaddr) 
			{
			data++;
			ioctl(ofd,MBUSIOCSSUBADDR,subaddr);
			buf[0] = *data++;
			write(ofd, &buf,1);
			len -= 2;
			}
		}
	close(ofd);
	return ack;
}

int main(void)
{
	int ofd, n, i,count; 
	unsigned char buf[128];

	i = write_block(0x43, init, sizeof(init));	/*write a block of bytes*/

	/*Read 125 bytes MAX is 128*/

	if ((ofd = open(MBUSDEVICE, O_RDWR)) < 1) {
		printf("ERROR: failed to open MBUS device %s\n", MBUSDEVICE);
		exit(1);
	}

	ioctl(ofd,MBUSIOCSSLADDR,0x43);		/*set slave address to access*/
	
	/*write a single byte*/
	ioctl(ofd,MBUSIOCSSUBADDR,0x06);	/*set subaddress*/
	buf[0] = 0x0b;				/*set data to write*/
	write(ofd, &buf,1);			/*write it*/

	/*read a block of address starting at sub address 0*/			
	for(n=0;n < 128;n++)		/*clear buf*/
		buf[n]= 0;

	ioctl(ofd,MBUSIOCSSUBADDR,0x00);	/*set starting sub address*/

	count = read(ofd, &buf,125);		/*read 125 bytes count should equal bytes read*/

	for(n=0;n < count;n++)
		printf("i2c reg 0x%02x = 0x%02x\n",n,buf[n]);	/*print them*/

	close(ofd);

	exit(0);
	return 0;
} /* main */
