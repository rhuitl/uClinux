#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>


#define SERIALPORT     "/dev/ttyS0"	/* Serial port to read from */
#define CYCLE		(1000 * 500)	/* Delta between samples (us) */


int rts_line = TIOCM_RTS;         /* ioctl reference to rts line      */
int fd_metex, fd_et;
struct termios newtio;

int main(int argc, char *argv[])
{
	int fd;
	struct termios tios;
	int rts = TIOCM_RTS;
	char buf[14];
	int l;
	int res;

	close(0);	
	fd = open(SERIALPORT, O_RDWR | O_NOCTTY | O_SYNC);
	if (fd == -1) {
		res = 1;
		fprintf(stderr, "cannot open %s\n", SERIALPORT);
	} else {
		close(2);

		tios.c_cflag = B1200 | CS7 | CSTOPB | CREAD | CLOCAL;
		tios.c_iflag = 0;
		tios.c_oflag = 0;
		tios.c_lflag = 0;
		tios.c_cc[VEOL] = 13;
		//tios.c_cc[VMIN] = 14;
		tcsetattr(fd, TCSANOW, &tios);
		ioctl(fd, TIOCMBIC, &rts);
	
		for (;;) {
	printf("Sleeping...\n");fflush(stdout);
			usleep(CYCLE);
	printf("Writing...\n");fflush(stdout);
			write(fd, "D", 1);
	printf("Reading...\n");fflush(stdout);
			for (l=0; l<14; l++) {
				read(fd, buf+l, 1);
				write(1, buf+l, 1);
			}
			//read(fd, buf, 14);
	printf("Decoding...\n");fflush(stdout);
			buf[13] = '\0';
			l = strlen(buf);
			if (l != write(1, buf, l)) {
				res = 0;
				break;
			}
		}
		ioctl(fd, TIOCMBIS, &rts);
		close(fd);
	}
	close(1);
	return res;
}
	
