#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <string.h>
#include <termios.h>
#include <sys/poll.h>
#include <dirent.h>
#include <ctype.h>


#define SERIALPORT	"/dev/ttyS0"	/* Serial line to read */

static inline void killAll(const char *name, int sig) {
DIR		*d;
struct dirent	*e;
char		 fn[NAME_MAX];
	d = opendir("/proc");
	if (!d) return;
	while ((e = readdir(d)) != NULL) {
	FILE *fp;
	char *p;
		/* We only care about this starting with a digit */
		if (!isdigit(*e->d_name)) continue;
		if (atoi(e->d_name) == getpid()) continue;
		/* Build the file name up */
		strcpy(fn, "/proc/");
		strcpy(fn+6, e->d_name);
		strcat(fn+6, "/status");
		/* Read the process name */
		fp = fopen(fn, "r");
		if (fp == NULL)
			continue;
		if (fgets(fn, NAME_MAX-1, fp) == NULL) {
			fclose(fp);
			continue;
		}
		fclose(fp);
		/* Now extract the second field and trim the trailing new line */
		fn[NAME_MAX-1] = '\0';
		p = strchr(fn, '\n');
		if (p != NULL) *p = '\0';
		for (p=fn; *p != '\0' && !isspace(*p); p++);
		while (*p != '\0' && isspace(*p)) p++;
		if (*p == '\0') continue;
		/* Send the signal */
		if (strcmp(p, name) == 0) {
		pid_t pid;
			pid = atoi(e->d_name);
			if (pid > 1)
				kill(atoi(e->d_name), sig);
		}
	}
	closedir(d);
}

int main(int argc, char *argv[]) {
	int fd;
	struct termios tios;
	struct pollfd pfd;
	char cbuf[13];
	char buf[13];
	int pos = 0;
	int state = 0;
	char c;

	killAll("r2100", 9);
	close(0);
	/* Open serial port */
	fd = open(SERIALPORT, O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "cannot open %s\n", SERIALPORT);
		return 1;
	}
	close(2);

	/* Configure serial port */
	tcgetattr(fd, &tios);
	tios.c_lflag &= ~ICANON;
	tios.c_lflag &= ~ISIG;
	tios.c_cflag &= ~CSIZE;
	tios.c_cflag &= ~CBAUD;
	tios.c_cflag |= CS8 | B9600 | CLOCAL | CREAD;
	tios.c_cc[VEOL] = 0x02;
	tios.c_cc[VEOL2] = 0x03;
	tcsetattr(fd, TCSANOW, &tios);

	/* Set up for the poll call */
	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;

	buf[0] = '\0';

	/* Wait for stuff to happen */
	for (;;) {
		/* Wait for serial input */
		if (poll(&pfd, 1, -1) == 1) {
			if (pfd.revents & pfd.events) {
				if (1 == read(fd, &c, 1)) {
					if (state == 0 && c == 0x02) {
						state = 1;
						pos = 0;
					} else if (state && c == 0x03) {
						cbuf[pos++] = '\n';
						cbuf[pos] = '\0';
						if (strcmp(buf, cbuf)) {
							strcpy(buf, cbuf);
							write(1, buf, strlen(buf));
						}
						state = 0;
					} else if (state) {
						cbuf[pos++] = c;
						if (pos == 11)
							pos--;
					}
				}
			} else
				break;
		}
	}
	return 0;
}
