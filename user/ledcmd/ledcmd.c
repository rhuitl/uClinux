#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <linux/ledman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

void usage(int rc)
{
	printf("usage: ledcmd [-h?] (-c|-s|-f <led>)\n\n"
		"\t-h?\tthis help\n"
		"\t-c\tclear LED (turn it off)\n"
		"\t-s\tset LED (turn it on)\n"
		"\t-f\tflash LED (make it flash)\n\n");
	exit(rc);
}

int main(int argc, char *argv[])
{
	int cmd, led, c;

	cmd = led = -1;

	while ((c = getopt(argc, argv, "?hs:f:c:")) > 0) {
		switch (c) {
		case 's':
			cmd = LEDMAN_CMD_ON;
			led = atoi(optarg);
			break;
		case 'c':
			cmd = LEDMAN_CMD_OFF;
			led = atoi(optarg);
			break;
		case 'f':
			cmd = LEDMAN_CMD_FLASH;
			led = atoi(optarg);
			break;
		case '?':
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (cmd < 0)
		usage(1);

	if ((led < 0) || (led >= LEDMAN_MAX)) {
		printf("ERROR: LED number out of range (0-%d)\n", LEDMAN_MAX);
		return -1;
	}

	ledman_cmd(cmd, led);
	return 0;
}
