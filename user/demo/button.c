#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include "../../modules/io/sgio.h"

/* Which SGIO input is the button? counting from zero
 */
#define BUTTON_NUM	1

/* How long to keep the LED lit after button release in s */
#define LED_TIME	2


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
	struct sgio_write_output_s outs;
	struct timeval tv, stv;
	int sleeptime;

	stv.tv_sec = 0;
	stv.tv_usec = 0;
	close(0);
	fd = open("/dev/sgio", O_RDONLY);
	if (fd >= 0) {
		previ = 2;
		close(2);
		for (;;) {
			gettimeofday(&tv, NULL);
			i = ioctl(fd, SGIO_READ_INPUT, BUTTON_NUM);
			if (i != previ) {
				if (1 != write(1, i?"1":"0", 1))
					return 0;
				if (i) {	/* Do stuff on off transition */
					outs.number = BUTTON_NUM;
					outs.value = 1;
					ioctl(fd, SGIO_WRITE_OUTPUT, &outs);
					stv.tv_sec = tv.tv_sec + LED_TIME;
					stv.tv_usec = tv.tv_usec;
				}
				previ = i;
				sleeptime = DEBOUNCE_TIME;
			} else
				sleeptime = POLL_RATE;
			if (stv.tv_usec != 0 && stv.tv_sec != 0) {
				if (stv.tv_sec < tv.tv_sec ||
						(stv.tv_sec == tv.tv_sec &&
						 stv.tv_usec <= tv.tv_usec)) {
					stv.tv_sec = 0;
					stv.tv_usec = 0;
					outs.number = BUTTON_NUM;
					outs.value = 0;
					ioctl(fd, SGIO_WRITE_OUTPUT, &outs);
				}
			}
			usleep(sleeptime);
		}
	}
	fprintf(stderr, "cannot open %s\n", "/dev/sgio");
	return 1;
}
