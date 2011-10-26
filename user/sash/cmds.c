/*
 * Modifications for uClinux
 * Copyright (C) 1998  Kenneth Albanowski <kjahds@kjahds.com>
 *
 * Original code
 * Copyright (c) 1993 by David I. Bell
 * Permission is granted to use, distribute, or modify this source,
 * provided that this copyright notice remains intact.
 *
 * Most simple built-in commands are here.
 */

#include "sash.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <errno.h>
#ifdef EMBED
#include <config/autoconf.h>
#endif

void
do_echo(argc, argv)
	char	**argv;
{
	BOOL	first;

	first = TRUE;
	while (argc-- > 1) {
		if (!first)
			fputc(' ', stdout);
		first = FALSE;
		fputs(*++argv, stdout);
	}
	fputc('\n', stdout);
}


void
do_pwd(argc, argv)
	char	**argv;
{
	char	buf[PATHLEN];

	if (getcwd(buf, PATHLEN) == NULL) {
		fprintf(stderr, "Cannot get current directory\n");
		return;
	}

	printf("%s\n", buf);
}

void
do_time(argc, argv)
	char ** argv;
{
	struct timeval tv;
	gettimeofday(&tv, 0);
	printf("Time of day = %d.%6.6d seconds\n", tv.tv_sec, tv.tv_usec);
}

void
do_cd(argc, argv)
	char	**argv;
{
	char	*path;

	if (argc > 1)
		path = argv[1];
	else {
		path = getenv("HOME");
		if (path == NULL) {
			fprintf(stderr, "No HOME environment variable\n");
			return;
		}
	}

	if (chdir(path) < 0)
		perror(path);
}


void
do_mkdir(argc, argv)
	char	**argv;
{
	int state = 0, mode = -1;

	while (argc-- > 1) {
		if (state == 0) {
			if (strcmp(argv[1], "-m") == 0)
				state = 1;
			else if (mkdir(argv[1], 0777) < 0)
				perror(argv[1]);
			else if (mode != -1 && chmod(argv[1], mode) < 0)
				perror(argv[1]);
		} else if (state == 1) {
			mode = strtol(argv[1], NULL, 8);
			state = 0;
		}
		argv++;
	}
}

void
do_sleep(argc, argv) 
	char	**argv;
{
	if (argc > 1)
		sleep(atoi(argv[1]));
}

void
do_mknod(argc, argv)
	char	**argv;
{
	char	*cp;
	int	mode;
	int	major;
	int	minor;

	mode = 0666;

	if (strcmp(argv[2], "b") == 0)
		mode |= S_IFBLK;
	else if (strcmp(argv[2], "c") == 0)
		mode |= S_IFCHR;
	else {
		fprintf(stderr, "Bad device type\n");
		return;
	}

	major = 0;
	cp = argv[3];
	while (isdecimal(*cp))
		major = major * 10 + *cp++ - '0';

	if (*cp || (major < 0) || (major > 255)) {
		fprintf(stderr, "Bad major number\n");
		return;
	}

	minor = 0;
	cp = argv[4];
	while (isdecimal(*cp))
		minor = minor * 10 + *cp++ - '0';

	if (*cp || (minor < 0) || (minor > 255)) {
		fprintf(stderr, "Bad minor number\n");
		return;
	}

	if (mknod(argv[1], mode, major * 256 + minor) < 0)
		perror(argv[1]);
}


void
do_rmdir(argc, argv)
	char	**argv;
{
	while (argc-- > 1) {
		if (rmdir(argv[1]) < 0)
			perror(argv[1]);
		argv++;
	}
}


void
do_sync(argc, argv)
	char	**argv;
{
#ifdef CONFIG_USER_FLATFSD_FLATFSD
	system("exec flatfsd -s");
#endif
	sync();
}


void
do_rm(argc, argv)
	char	**argv;
{
	while (argc-- > 1) {
		if (unlink(argv[1]) < 0)
			perror(argv[1]);
		argv++;
	}
}


void
do_chmod(argc, argv)
	char	**argv;
{
	char	*cp;
	int	mode;

	mode = 0;
	cp = argv[1];
	while (isoctal(*cp))
		mode = mode * 8 + (*cp++ - '0');

	if (*cp) {
		fprintf(stderr, "Mode must be octal\n");
		return;
	}
	argc--;
	argv++;

	while (argc-- > 1) {
		if (chmod(argv[1], mode) < 0)
			perror(argv[1]);
		argv++;
	}
}


void
do_chown(argc, argv)
	char	**argv;
{
	char		*cp;
	int		uid;
	struct passwd	*pwd;
	struct stat	statbuf;

	cp = argv[1];
	if (isdecimal(*cp)) {
		uid = 0;
		while (isdecimal(*cp))
			uid = uid * 10 + (*cp++ - '0');

		if (*cp) {
			fprintf(stderr, "Bad uid value\n");
			return;
		}
	} else {
		pwd = getpwnam(cp);
		if (pwd == NULL) {
			fprintf(stderr, "Unknown user name\n");
			return;
		}

		uid = pwd->pw_uid;
	}

	argc--;
	argv++;

	while (argc-- > 1) {
		argv++;
		if ((stat(*argv, &statbuf) < 0) ||
			(chown(*argv, uid, statbuf.st_gid) < 0))
				perror(*argv);
	}
}


void
do_chgrp(argc, argv)
	char	**argv;
{
	char		*cp;
	int		gid;
	struct group	*grp;
	struct stat	statbuf;

	cp = argv[1];
	if (isdecimal(*cp)) {
		gid = 0;
		while (isdecimal(*cp))
			gid = gid * 10 + (*cp++ - '0');

		if (*cp) {
			fprintf(stderr, "Bad gid value\n");
			return;
		}
	} else {
		grp = getgrnam(cp);
		if (grp == NULL) {
			fprintf(stderr, "Unknown group name\n");
			return;
		}

		gid = grp->gr_gid;
	}

	argc--;
	argv++;

	while (argc-- > 1) {
		argv++;
		if ((stat(*argv, &statbuf) < 0) ||
			(chown(*argv, statbuf.st_uid, gid) < 0))
				perror(*argv);
	}
}


void
do_touch(argc, argv)
        char    **argv;
{
        char            *name;
        int             fd;
        struct  utimbuf now;

        time(&now.actime);
        now.modtime = now.actime;

        while (argc-- > 1) {
                name = *(++argv);

                if (utime(name, &now) <0)
                {
                fd = open(name, O_CREAT | O_WRONLY | O_EXCL, 0666);
                if (fd >= 0)
                        {
                        close(fd);
                        continue;
                        }
                perror(name);
                }
        }
}


void
do_mv(argc, argv)
	char	**argv;
{
	int	dirflag;
	char	*srcname;
	char	*destname;
	char	*lastarg;

	lastarg = argv[argc - 1];

	dirflag = isadir(lastarg);

	if ((argc > 3) && !dirflag) {
		fprintf(stderr, "%s: not a directory\n", lastarg);
		return;
	}

	while (argc-- > 2) {
		srcname = *(++argv);
		if (access(srcname, 0) < 0) {
			perror(srcname);
			continue;
		}

		destname = lastarg;
		if (dirflag)
			destname = buildname(destname, srcname);

		if (rename(srcname, destname) >= 0)
			continue;

		if (errno != EXDEV) {
			perror(destname);
			continue;
		}

		if (!copyfile(srcname, destname, TRUE))
			continue;

		if (unlink(srcname) < 0)
			perror(srcname);
	}
}


void
do_ln(argc, argv)
	char	**argv;
{
	int	dirflag;
	char	*srcname;
	char	*destname;
	char	*lastarg;

	if (argv[1][0] == '-') {
		if (strcmp(argv[1], "-s")) {
			fprintf(stderr, "Unknown option\n");
			return;
		}

		if (argc != 4) {
			fprintf(stderr, "Wrong number of arguments for symbolic link\n");
			return;
		}

#ifdef	S_ISLNK
		if (symlink(argv[2], argv[3]) < 0)
			perror(argv[3]);
#else
		fprintf(stderr, "Symbolic links are not allowed\n");
#endif
		return;
	}

	/*
	 * Here for normal hard links.
	 */
	lastarg = argv[argc - 1];
	dirflag = isadir(lastarg);

	if ((argc > 3) && !dirflag) {
		fprintf(stderr, "%s: not a directory\n", lastarg);
		return;
	}

	while (argc-- > 2) {
		srcname = *(++argv);
		if (access(srcname, 0) < 0) {
			perror(srcname);
			continue;
		}

		destname = lastarg;
		if (dirflag)
			destname = buildname(destname, srcname);

		if (link(srcname, destname) < 0) {
			perror(destname);
			continue;
		}
	}
}


void
do_cp(argc, argv)
	char	**argv;
{
	BOOL	dirflag;
	char	*srcname;
	char	*destname;
	char	*lastarg;

	lastarg = argv[argc - 1];

	dirflag = isadir(lastarg);

	if ((argc > 3) && !dirflag) {
		fprintf(stderr, "%s: not a directory\n", lastarg);
		return;
	}

	while (argc-- > 2) {
		destname = lastarg;
		srcname = *++argv;
		if (dirflag)
			destname = buildname(destname, srcname);

		(void) copyfile(srcname, destname, FALSE);
	}
}


void
do_mount(argc, argv)
	char	**argv;
{
	char	*str;
	char	*type;

	argc--;
	argv++;
	type = "minix";

	while ((argc > 0) && (**argv == '-')) {
		argc--;
		str = *argv++ ;

		while (*++str) switch (*str) {
			case 't':
				if ((argc <= 0) || (**argv == '-')) {
					fprintf(stderr, "Missing file system type\n");
					return;
				}

				type = *argv++;
				argc--;
				break;

			default:
				fprintf(stderr, "Unknown option\n");
				return;
		}
	}

	if (argc != 2) {
		fprintf(stderr, "Wrong number of arguments for mount\n");
		return;
	}

	if (mount(argv[0], argv[1], type, 0, 0) < 0)
		perror("mount failed");
}


void
do_umount(argc, argv)
	char	**argv;
{
	if (umount(argv[1]) < 0)
		perror(argv[1]);
}


void
do_cmp(argc, argv)
	char	**argv;
{
	int		fd1;
	int		fd2;
	int		cc1;
	int		cc2;
	long		pos;
	char		*srcname;
	char		*destname;
	char		*lastarg;
	char		*bp1;
	char		*bp2;
	char		*buf1;
	char		*buf2;
	struct	stat	statbuf1;
	struct	stat	statbuf2;
	
	if (stat(argv[1], &statbuf1) < 0) {
		perror(argv[1]);
		return;
	}

	if (stat(argv[2], &statbuf2) < 0) {
		perror(argv[2]);
		return;
	}

	if ((statbuf1.st_dev == statbuf2.st_dev) &&
		(statbuf1.st_ino == statbuf2.st_ino))
	{
		printf("Files are links to each other\n");
		return;
	}

	if (statbuf1.st_size != statbuf2.st_size) {
		printf("Files are different sizes\n");
		return;
	}
	
	fd1 = open(argv[1], 0);
	if (fd1 < 0) {
		perror(argv[1]);
		return;
	}

	fd2 = open(argv[2], 0);
	if (fd2 < 0) {
		perror(argv[2]);
		close(fd1);
		return;
	}
	
	buf1 = malloc(8192-16);
	buf2 = malloc(8192-16);

	pos = 0;
	while (TRUE) {
		if (intflag)
			goto closefiles;

		cc1 = read(fd1, buf1, 8192-16);
		if (cc1 < 0) {
			perror(argv[1]);
			goto closefiles;
		}

		cc2 = read(fd2, buf2, 8192-16);
		if (cc2 < 0) {
			perror(argv[2]);
			goto closefiles;
		}

		if ((cc1 == 0) && (cc2 == 0)) {
			printf("Files are identical\n");
			goto closefiles;
		}

		if (cc1 < cc2) {
			printf("First file is shorter than second\n");
			goto closefiles;
		}

		if (cc1 > cc2) {
			printf("Second file is shorter than first\n");
			goto closefiles;
		}

		if (memcmp(buf1, buf2, cc1) == 0) {
			pos += cc1;
			continue;
		}

		bp1 = buf1;
		bp2 = buf2;
		while (*bp1++ == *bp2++)
			pos++;

		printf("Files differ at byte position %ld\n", pos);
		goto closefiles;
	}

closefiles:
	close(fd1);
	close(fd2);
	free(buf1);
	free(buf2);
}


void
do_more(argc, argv)
	char	**argv;
{
	FILE	*fp;
	char	*name;
	int	ch;
	int	line;
	int	col;
	char	buf[80];

	while (argc-- > 1) {
		name = *(++argv);

		fp = fopen(name, "r");
		if (fp == NULL) {
			perror(name);
			return;
		}

		printf("<< %s >>\n", name);
		line = 1;
		col = 0;

		while (fp && ((ch = fgetc(fp)) != EOF)) {
			switch (ch) {
				case '\r':
					col = 0;
					break;

				case '\n':
					line++;
					col = 0;
					break;

				case '\t':
					col = ((col + 1) | 0x07) + 1;
					break;

				case '\b':
					if (col > 0)
						col--;
					break;

				default:
					col++;
			}

			putchar(ch);
			if (col >= 80) {
				col -= 80;
				line++;
			}

			if (line < 24)
				continue;

			if (col > 0)
				putchar('\n');

			printf("--More--");
			fflush(stdout);

			if (intflag || (read(0, buf, sizeof(buf)) < 0)) {
				if (fp)
					fclose(fp);
				return;
			}

			ch = buf[0];
			if (ch == ':')
				ch = buf[1];

			switch (ch) {
				case 'N':
				case 'n':
					fclose(fp);
					fp = NULL;
					break;

				case 'Q':
				case 'q':
					fclose(fp);
					return;
			}

			col = 0;
			line = 1;
		}
		if (fp)
			fclose(fp);
	}
}


void
do_exit(argc, argv)
	char	**argv;
{
	exit(0);
}


void
do_setenv(argc, argv)
	char	**argv;
{
	setenv(argv[1], argv[2], 1);
}


void
do_printenv(argc, argv)
	char	**argv;
{
	char		**env;
	extern char	**environ;
	int		len;

	env = environ;

	if (argc == 1) {
		while (*env)
			printf("%s\n", *env++);
		return;
	}

	len = strlen(argv[1]);
	while (*env) {
		if ((strlen(*env) > len) && (env[0][len] == '=') &&
			(memcmp(argv[1], *env, len) == 0))
		{
			printf("%s\n", &env[0][len+1]);
			return;
		}
		env++;
	}
}


void
do_umask(argc, argv)
	char	**argv;
{
	char	*cp;
	int	mask;

	if (argc <= 1) {
		mask = umask(0);
		umask(mask);
		printf("%03o\n", mask);
		return;
	}

	mask = 0;
	cp = argv[1];
	while (isoctal(*cp))
		mask = mask * 8 + *cp++ - '0';

	if (*cp || (mask & ~0777)) {
		fprintf(stderr, "Bad umask value\n");
		return;
	}

	umask(mask);
}


void
do_kill(argc, argv)
	char	**argv;
{
	char	*cp;
	int	sig;
	int	pid;

	sig = SIGTERM;

	if (argv[1][0] == '-') {
		cp = &argv[1][1];
		if (strcmp(cp, "HUP") == 0)
			sig = SIGHUP;
		else if (strcmp(cp, "INT") == 0)
			sig = SIGINT;
		else if (strcmp(cp, "QUIT") == 0)
			sig = SIGQUIT;
		else if (strcmp(cp, "ILL") == 0)
			sig = SIGILL;
		else if (strcmp(cp, "TRAP") == 0)
			sig = SIGTRAP;
		else if (strcmp(cp, "ABRT") == 0)
			sig = SIGABRT;
		else if (strcmp(cp, "IOT") == 0)
			sig = SIGIOT;
		else if (strcmp(cp, "BUS") == 0)
			sig = SIGBUS;
		else if (strcmp(cp, "FPE") == 0)
			sig = SIGFPE;
		else if (strcmp(cp, "KILL") == 0)
			sig = SIGKILL;
		else if (strcmp(cp, "USR1") == 0)
			sig = SIGUSR1;
		else if (strcmp(cp, "SEGV") == 0)
			sig = SIGSEGV;
		else if (strcmp(cp, "USR2") == 0)
			sig = SIGUSR2;
		else if (strcmp(cp, "PIPE") == 0)
			sig = SIGPIPE;
 		else if (strcmp(cp, "ALRM") == 0)
			sig = SIGALRM;
 		else if (strcmp(cp, "TERM") == 0)
			sig = SIGTERM;
#ifdef SIGSTKFLT
 		else if (strcmp(cp, "STKFLT") == 0)
			sig = SIGSTKFLT;
#endif
 		else if (strcmp(cp, "CHLD") == 0)
			sig = SIGCHLD;
		else if (strcmp(cp, "CONT") == 0)
			sig = SIGCONT;
		else if (strcmp(cp, "STOP") == 0)
			sig = SIGSTOP;
		else if (strcmp(cp, "TSTP") == 0)
			sig = SIGTSTP;
 		else if (strcmp(cp, "TTIN") == 0)
			sig = SIGTTIN;
 		else if (strcmp(cp, "TTOU") == 0)
			sig = SIGTTOU;
 		else if (strcmp(cp, "URG") == 0)
			sig = SIGURG;
 		else if (strcmp(cp, "PWR") == 0)
			sig = SIGPWR;
		else {
			sig = 0;
			while (isdecimal(*cp))
				sig = sig * 10 + *cp++ - '0';

			if (*cp) {
				fprintf(stderr, "Unknown signal\n");
				exit_code = 1;
				return;
			}
		}
		argc--;
		argv++;
	}

	while (argc-- > 1) {
		cp = *++argv;
		pid = 0;
		while (isdecimal(*cp))
			pid = pid * 10 + *cp++ - '0';

		if (*cp) {
			fprintf(stderr, "Non-numeric pid\n");
			exit_code = 1;
			return;
		}

		if (kill(pid, sig) < 0) {
			perror(*argv);
			exit_code = 1;
		}
	}
}

/* END CODE */
