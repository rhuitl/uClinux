
#include <stdio.h>
#include <fcntl.h>
#include <linux/flash.h>

main(int argc, char *argv[])
{
	int	fd;

	if (argc != 2) {
		puts("usage: erase /dev/flashX\n");
		exit(1);
	}

	if ((fd = open(argv[1], O_RDWR)) < 0) {
		perror("open");
		exit(1);
	}

	if (ioctl(fd, FLASHIO_ERASEALL, 0L) == -1) {
		perror("ioctl(FLASHIO_ERASEALL)");
		close(fd);
		exit(1);
	}

	close(fd);
	exit(0);
}

