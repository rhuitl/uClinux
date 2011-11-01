/*
 * ipcamd configuration
 *
 * Author: Robert Huitl <robert@huitl.de> (2011)
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "mtd-abi.h"


int read_config(struct cam_config* c)
{
	printf("Reading configuration at %s\n", CONFIG_MTD);

	int f = open(CONFIG_MTD, O_RDONLY);
	if(f < 0) {
		perror("Cannot open MTD device");
		return f;
	}

	int ret = read(f, c, sizeof(*c));
	if(ret != sizeof(*c)) {
		perror("Cannot read config data");
		return -1;
	}
	close(f);

	if(c->valid == 0 || c->valid == 0xFF) {
		init_config(c);
		printf("initialized ");
		print_config(c);
		write_config(c);
	}

	return 0;
}

int erase_config()
{
	struct mtd_info_user mtd_info;
	struct erase_info_user erase_info;

	printf("Erasing configuration data\n");

	int f = open(CONFIG_MTD, O_RDWR | O_SYNC);
	if(f < 0) {
		perror("Cannot open mtd device");
		return f;
	}

	if(ioctl(f, MEMGETINFO, &mtd_info)) {
		perror("Cannot get mtd device info");
		close(f);
		return -1;
	}

	erase_info.length = mtd_info.erasesize;
	//printf("Erasing in blocks of %d bytes\n", erase_info.length);

	for (erase_info.start = 0;
		 erase_info.start < mtd_info.size;
		 erase_info.start += mtd_info.erasesize) {

		ioctl(f, MEMUNLOCK, &erase_info);
		if(ioctl(f, MEMERASE, &erase_info)) {
			perror("Cannot erase mtd device");
			close(f);
			return -1;
		}
	}
	close(f);
	return 0;
}

int write_config(struct cam_config* c)
{
	if(erase_config())
		return -1;

	printf("Writing configuration to %s\n", CONFIG_MTD);

	int f = open(CONFIG_MTD, O_RDWR | O_SYNC);
	if(f < 0) {
		perror("Cannot open MTD device");
		return f;
	}

	int ret = write(f, c, sizeof(*c));
	if(ret != sizeof(*c)) {
		perror("Cannot write config data");
		return -1;
	}
	close(f);
	return 0;
}

void print_config(struct cam_config* c)
{
	struct in_addr ia;
	ia.s_addr = c->ip;

	printf("config: valid:%d version:%d ip:%s name:%s\n",
	       c->valid, c->version, inet_ntoa(ia), c->cam_name);
}

void init_config(struct cam_config* c)
{
	c->valid = 1;
	c->version = 0;
	c->ip = (1<<24) | (11<<16) | (168<<8) | 192;
	strcpy(c->cam_name, "devcam");
}
