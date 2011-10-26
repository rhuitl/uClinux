
#include "sash.h"

#include <linux/autoconf.h>

#include <fcntl.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <unistd.h>

#if 0
char psbuf[256];
char name[40];
int pid, state;
char statec;

void
do_ps(argc, argv)
	char	**argv;
{
	int i;
	int h;
	int max;
	FILE * f;
	DIR * d;
	struct dirent * de;
	int l;
	
	printf("  PID TTY STAT  TIME COMMAND\n");
	
	
	d = opendir("/proc");
	if (!d)
		return;
	
	while (de = readdir(d)) {
		for(i=0;i<strlen(de->d_name);i++)
			if (!isdigit(de->d_name[i]))
				goto next;
		
		sprintf(psbuf, "/proc/%s/stat", de->d_name);
		h = open(psbuf, O_RDONLY);
		
		if (h==-1)
			continue;
			
		l = read(h, psbuf, 255);
		if (l<=0) {
			perror("Unable to read status");
			close(h);
			continue;
		}
		
		psbuf[l] = '\0';
		psbuf[255] = '\0';
		
		
		if (sscanf(psbuf, 
			"%d %s %c",
			&pid, name, &statec)<3)
			{
			perror("Unable to parse status");
			close(h);
			continue;
		}
		
		state = statec;
		
		close(h);
		
		sprintf(psbuf, "/proc/%s/cmdline", de->d_name);
		h = open(psbuf, O_RDONLY);
		
		if (h == -1) {
			perror("Unable to open cmdline");
			continue;
		}
		
		l = read(h, psbuf, 255);
		if (l < 0) {
			perror("Unable to read cmdline");
			close(h);
			continue;
		}
		
		close(h);
		
		psbuf[255] = psbuf[l] = '\0';
		
		printf("%5d %3s %c     --:-- %s\n", pid, "", state, psbuf);
	next:
	}
	
	closedir(d);
}
#endif

void
do_cat(argc, argv)
	char	**argv;
{
	int	fd;
	char	*name;
	size_t	l;
	char	buf[256];

	while (argc-- > 1) {
		if (intflag) {
			return;
		}
		name = *(++argv);

		fd = open(name, O_RDONLY);
		if (fd < 0) {
			perror(name);
			return;
		}

		while ((l = read(fd, buf, sizeof(buf))) > 0) {
			fwrite(buf, 1, l, stdout);
		}
		close(fd);
	}
}
