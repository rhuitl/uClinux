/****************************************************************************/

/*
 *	setmac.c --  Set MAC addresses for eth devices from FLASH
 *
 *	(C) Copyright 2004, Greg Ungerer <gerg@snapgear.com>
 */

/****************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

/****************************************************************************/

/*
 *	Define the maxiumum number of ethernet devices we should try
 *	and configure. Also define the default number we try to configure.
 */
#define	MAXETHS		16
#define	DEFAULTETHS	16

#ifndef ETHPREFIX
#define ETHPREFIX "eth"
#endif

/*
 *	Define the default flash device to use to get MAC addresses from.
 */
#define	DEFAULTFLASH	"/dev/flash/ethmac"

/****************************************************************************/

/*
 *	Define the table of default MAC addresses. What to use if we can't
 *	find any other good MAC addresses.
 */
unsigned char mactable[MAXETHS * 6] = {
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x01,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x02,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x03,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x04,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x05,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x06,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x07,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x08,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x09,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x0a,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x0b,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x0c,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x0d,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x0e,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x0f,
	0x00, 0xd0, 0xcf, 0x00, 0x00, 0x10,
};

int numeths = DEFAULTETHS;
int debug = 0;

/****************************************************************************/

/*
 *	Search for a mtd partition in /proc/mtd.
 *	Assumes that each line starts with the device name followed
 *	by a ':', and the partition name is enclosed by quotes.
 */
char *findmtddevice(char *mtdname)
{
	FILE *f;
	char buf[80];
	int found;
	static char device[80];
	char *p, *q;

	f = fopen("/proc/mtd", "r");
	if (!f) {
		perror("setmac: open /proc/mtd failed");
		return NULL;
	}

	found = 0;
	while (!found && fgets(buf, sizeof(buf), f)) {
		p = strchr(buf, ':');
		if (!p)
			continue;
		*p++ = '\0';

		p = strchr(p, '"');
		if (!p)
			continue;
		p++;

		q = strchr(p, '"');
		if (!q)
			continue;
		*q = '\0';

		if (strcmp(p, mtdname) == 0) {
			found = 1;
			break;
		}
	}
	fclose(f);

	if (found) {
		sprintf(device, "/dev/%s", buf);
		return device;
	} else {
		fprintf(stderr, "setmac: mtd device '%s' not found\n", mtdname);
		return NULL;
	}
}

/****************************************************************************/

void *memstr(void *m, const char *s, size_t n)
{
	int slen;
	void *end;

	slen = strlen(s);
	if (!slen || slen > n)
		return NULL;

	for (end=m+n-slen; m<=end; m++)
		if (memcmp(m, s, slen)==0)
			return m;

	return NULL;

}

/****************************************************************************/

#define REDBOOTSIZE 4096

void readmacredboot(char *flash, char *redbootconfig)
{
	int fd, i;
	off_t flashsize;
	void *m, *mac;
	char name[32];

	if ((fd = open(flash, O_RDONLY)) < 0) {
		perror("setmac: failed to open MAC flash");
		return;
	}

	m = malloc(REDBOOTSIZE);
	if (!m) {
		fprintf(stderr, "setmac: malloc failed\n");
		close(fd);
		return;
	}

	flashsize = read(fd, m, REDBOOTSIZE);
	if (flashsize < 0) {
		perror("setmac: failed to read MAC flash");
		close(fd);
		free(m);
		return;
	}

	for (i = 0; (i < numeths); i++) {
		snprintf(name, sizeof(name), redbootconfig, i);
		mac = memstr(m, name, flashsize);
		if (!mac) {
			fprintf(stderr, "setmac: redboot config '%s' not found\n",
					name);
			continue;
		}
		mac += strlen(name)+1;
		memcpy(&mactable[i*6], mac, 6);
	}

	free(m);
	close(fd);
}

/****************************************************************************/

void readmacflash(char *flash, off_t macoffset)
{
	int fd, i;
	off_t off;
	unsigned char mac[6];


	/*
	 *	Not that many possible MAC addresses, so lets just
	 *	read them all at once and cache them locally.
	 */
	if ((fd = open(flash, O_RDONLY)) < 0) {
		perror("setmac: failed to read MAC flash");
		return;
	}

	for (i = 0; (i < numeths); i++) {
		off = macoffset + (i * 6);
		if (lseek(fd, off, SEEK_SET) != off) {
			perror("setmac: failed to find eth MACS");
			break;
		}

		if (read(fd, &mac[0], 6) < 0) {
			perror("setmac: failed to read eth MACS");
			break;
		}

		/* Do simple checks for a valid MAC address */
		if ((mac[0] == 0) && (mac[1] == 0) && (mac[2] == 0) &&
		    (mac[3] == 0) && (mac[4] == 0) && (mac[5] == 0))
			continue;
		if ((mac[0] == 0xff) && (mac[1] == 0xff) && (mac[2] == 0xff) &&
		    (mac[3] == 0xff) && (mac[4] == 0xff) && (mac[5] == 0xff))
			continue;

		memcpy(&mactable[i*6], &mac[0], 6);
	}

	close(fd);
}

/****************************************************************************/

void runflashmac(void)
{
	FILE *fp;
	char cmd[32], result[32], *cp;
	unsigned int i, mac[6];

	for (i = 0; i < numeths; i++) {

		sprintf(cmd, "flash mac%d", i);
		fp = popen(cmd, "r");
		if (!fp)
			continue;
		cp = fgets(result, sizeof(result), fp);
		pclose(fp);

		if (!cp)
			continue;

		if (sscanf(cp, "%02x %02x %02x %02x %02x %02x", &mac[0], &mac[1],
				   	&mac[2], &mac[3], &mac[4], &mac[5]) != 6)
			continue;

		/* Do simple checks for a valid MAC address */
		if ((mac[0] == 0) && (mac[1] == 0) && (mac[2] == 0) &&
		    (mac[3] == 0) && (mac[4] == 0) && (mac[5] == 0))
			continue;
		if ((mac[0] == 0xff) && (mac[1] == 0xff) && (mac[2] == 0xff) &&
		    (mac[3] == 0xff) && (mac[4] == 0xff) && (mac[5] == 0xff))
			continue;

		mactable[i*6+0] = mac[0];
		mactable[i*6+1] = mac[1];
		mactable[i*6+2] = mac[2];
		mactable[i*6+3] = mac[3];
		mactable[i*6+4] = mac[4];
		mactable[i*6+5] = mac[5];
	}
}

/****************************************************************************/

void getmac(int port, unsigned char *mac)
{
	memcpy(mac, &mactable[port*6], 6);
}

/****************************************************************************/

void setmac(int port, unsigned char *mac)
{
	int pid, status;
	char eths[32];
	char macs[32];

	sprintf(eths, "%s%d", ETHPREFIX, port);
	sprintf(macs, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	if ((pid = vfork()) < 0) {
		perror("setmac: failed to fork()");
		return;
	}

	if (pid == 0) {
		/* we do not want to see the output unless debug is enabled */
		if (!debug) {
			close(0);
			close(1);
			close(2);
			open("/dev/null", O_RDWR);
			dup(0);
			dup(0);
		}
		execlp("ifconfig", "ifconfig", eths, "hw", "ether", macs, NULL);
		exit(1);
	}

	waitpid(pid, &status, 0);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		printf("Set %s to MAC address %s\n", eths, macs);
}

/****************************************************************************/

static int basemac(const char *p)
{
	unsigned int i, j, mac[6];


	if (sscanf(p, "%02x%*c%02x%*c%02x%*c%02x%*c%02x%*c%02x",
				mac, mac+1, mac+2, mac+3, mac+4, mac+5) != 6)
		return -1;

	for (i = 0; i < numeths; i++) {
		mactable[i*6+0] = mac[0];
		mactable[i*6+1] = mac[1];
		mactable[i*6+2] = mac[2];
		mactable[i*6+3] = mac[3];
		mactable[i*6+4] = mac[4];
		mactable[i*6+5] = mac[5];

		for (j=5; j>0; j--) {
			mac[j]++;
			if (mac[j] != 256)
				break;
			mac[j] = 0;
		}
	}

	return 0;
}

/****************************************************************************/

void usage(int rc)
{
	printf("usage: setmac [-hs?] [OPTION]...\n"
		"\t-b <base-mac>\n"
		"\t-s\n"
		"\t-f <flash-device>\n"
		"\t-m <mtd-name>\n"
		"\t-n <num-eth-interfaces>\n"
		"\t-o <offset>\n"
		"\t-p\n"
		"\t-r <redboot-config-name>\n");
	exit(rc);
}

/****************************************************************************/

int main(int argc, char *argv[])
{
	int i, p, c;
	unsigned char mac[6];
	char *flash = DEFAULTFLASH;
	char *mtdname = NULL;
	off_t macoffset = 0x24000;
	char *redboot = NULL;
	int swapmacs = 0;
	int runflash = 0;

	while ((c = getopt(argc, argv, "h?b:dspm:n:o:r:f:")) > 0) {
		switch (c) {
		case '?':
		case 'h':
			usage(0);
		case 'b':
			if (basemac(optarg) < 0) {
				printf("ERROR: invalid base MAC\n");
				exit(1);
			}
			flash = NULL;
			break;
		case 's':
			swapmacs++;
			break;
		case 'p':
			runflash++;
			break;
		case 'd':
			debug++;
			break;
		case 'f':
			flash = optarg;
			break;
		case 'm':
			mtdname = optarg;
			break;
		case 'n':
			numeths = atoi(optarg);
			if ((numeths < 0) || (numeths > MAXETHS)) {
				printf("ERROR: bad number of ethernets?\n");
				exit(1);
			}
			break;
		case 'o':
			macoffset = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			redboot = optarg;
			break;
		default:
			usage(1);
		}
	}

	if (mtdname)
		flash = findmtddevice(mtdname);

	if (runflash) {
		runflashmac();
	} else if (flash) {
		if (redboot)
			readmacredboot(flash, redboot);
		else
			readmacflash(flash, macoffset);
	}

	for (i = 0; (i < numeths); i++) {
		p = (swapmacs) ? (i^1) : i;
		getmac(p, &mac[0]);
		setmac(i, &mac[0]);
	}

	return 0;
}

/****************************************************************************/
