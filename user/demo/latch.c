#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "../../modules/io/sgio.h"

/* Which SGIO input is the button? counting from zero
 */
#define BUTTON_NUM	0

/* How long to latch the output in s */
#define LATCH_TIME	60


/* Define our poll timings.
 * We'll check for a state change every 20ms (fiftieth of a second) and
 * we'll provide a debounce delay of 50ms (twentieth of a second).
 */
#define POLL_RATE	(1000 * 20)
#define DEBOUNCE_TIME	(1000 * 50)

/* The main routine, wait for button state changes and output transitions
 */
int main(int argc, char *argv[]) {
	int fd;
	int i, previ;
	time_t t, st;
	int sleeptime;
	struct sgio_write_output_s outs;

	st = 0;
	close(0);
	fd = open("/dev/sgio", O_RDONLY);
	if (fd >= 0) {
		previ = 2;
		close(2);
		outs.number = BUTTON_NUM;
		outs.value = 0;
		ioctl(fd, SGIO_WRITE_OUTPUT, &outs);
		for (;;) {
			t = time(NULL);
			i = ioctl(fd, SGIO_READ_INPUT, BUTTON_NUM);
			if (i != previ) {
				if (i == 0) {
					if (1 != write(1, "0", 1))
						return 0;
					outs.number = BUTTON_NUM;
					outs.value = 1;
					ioctl(fd, SGIO_WRITE_OUTPUT, &outs);
					st = t + LATCH_TIME;
				} else if (previ == 2) {
					write(1, "1", 1);
					outs.number = BUTTON_NUM;
					outs.value = 0;
					ioctl(fd, SGIO_WRITE_OUTPUT, &outs);
				}
//				if (1 != write(1, i?"1":"0", 1))
//					return 0;
				previ = i;
				sleeptime = DEBOUNCE_TIME;
			} else
				sleeptime = POLL_RATE;
			if (st != 0 && st <= t) {
				st = 0;
				write(1, "1", 1);
				outs.number = BUTTON_NUM;
				outs.value = 0;
				ioctl(fd, SGIO_WRITE_OUTPUT, &outs);
			}
			usleep(sleeptime);
		}
	}
	fprintf(stderr, "cannot open %s\n", "/dev/sgio");
	return 1;
}
