/*
This file is part of ipcamd, an embedded web server for IP cameras.

Copyright (c) 2011-2013, Robert Huitl <robert@huitl.de>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
