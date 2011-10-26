#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <libgen.h>

int
main(int argc, char **argv)
{
	char *realprog;
	char *bn = basename(argv[0]);
	int fd;

	fd = open("/proc/self/oom_score_adj", O_WRONLY);
	if (fd >= 0) {
		write(fd, "-1000", 5);
		close(fd);
	} else {
		fd = open("/proc/self/oom_adj", O_WRONLY);
		if (fd >= 0) {
			write(fd, "-18", 3);
			close(fd);
		}
	}

	realprog = malloc(strlen(bn) + 10);
	if (!realprog) {
		perror("malloc");
		exit(1);
	}
	sprintf(realprog, "/.no_oom/%s", bn);
	execvp(realprog, argv);
	perror("execvp");
	exit(1);
}
