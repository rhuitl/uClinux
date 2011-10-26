#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

static unsigned char buf[16384];

main(int argc, char *argv[])
{
	int fd, pwm_fd;
	char *fname;
	int n, nw, nrd;
	unsigned char *p;
	int i;

	if (argc < 2) {
		fprintf(stderr, "usage: playrt file1 [file2...]\n");
		exit(1);
	}

	pwm_fd = open("/dev/pwm", 1);
	if (pwm_fd < 0) {
		perror("/dev/pwm");
		exit(1);
	}
	for (i = 1; i < argc; i++) {
		fname = argv[i];
		fd = open(fname, 0);
		if (fd < 0) {
			fprintf(stderr, "Cannot open %s\n", fname);
			perror("open");
			exit(2);
		}
		while ((n = read(fd, buf, sizeof(buf))) > 0) {
			p = buf;
			do {
				nw = write(pwm_fd, p, n);
				if (nw < 0) {
					perror("write /dev/pwm");
					exit(1);
				}
				n -= nw;
				p += nw;
			} while (n > 0);
		}
		close(fd);
	}
	close(pwm_fd);
}
