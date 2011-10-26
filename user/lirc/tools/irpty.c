/*      $Id: irpty.c,v 5.3 2000/03/25 12:09:41 columbus Exp $      */

/****************************************************************************
 ** irpty.c *****************************************************************
 ****************************************************************************
 *
 * irpty  - pseudo tty driver
 *          Connects to lircd via socket to receive infra-red codes
 *          and converts them to key strokes
 *
 * Copyright (C) 1996,97 Ralph Metzler <rjkm@thp.uni-koeln.de>
 * Copyright (C) 1998 Christoph Bartelmus <lirc@bartelmus.de>
 *
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include "lirc_client.h"

#define	BUFFSIZE 512

char *progname;

struct lirc_config *lconfig;

static int lsock, sigcaught;

void die(char *fmt,...)
{
	va_list args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	lirc_freeconfig(lconfig);
	lirc_deinit();
	exit(1);
}

static void sig_term(int sig)
{
	sigcaught = 1;
	return;
}

static void copy_loop(int ptym, int ignoreeof)
{
	pid_t child;
	int nread;
	char buf[BUFFSIZE];
	struct sigaction act;

	if ((child = fork()) < 0) {
		die("fork error");
	} else if (!child) {
		fd_set fds;
		while (1) {
			FD_ZERO(&fds);
			FD_SET(lsock, &fds);
			FD_SET(STDIN_FILENO, &fds);
			select(lsock + 1, &fds, NULL, NULL, NULL);
			
			if (FD_ISSET(STDIN_FILENO, &fds)) {
				if ((nread = read(STDIN_FILENO, buf, BUFFSIZE)) < 0)
					die("read error from stdin");
				else if (!nread)
					break;
				if (write(ptym, buf, nread) != nread)
					die("writen error to master pty");
			}
			if (FD_ISSET(lsock, &fds))
			{
				char *ir;
				char *irchars;
				int ret;
				
				while((ret=lirc_nextcode(&ir))==0)
				{
					if(ir==NULL) break;
					while((ret=lirc_code2char
					       (lconfig,ir,&irchars))==0 &&
					      irchars!=NULL)
					{
						if(write(ptym,irchars,strlen(irchars)) != strlen(irchars))
							die("writen error to master pty");
					}
					free(ir);
					if(ret==-1) break;
				}
				if(ret==-1) break;
			}
		}
		if (!ignoreeof)
			kill(getppid(), SIGTERM);
		lirc_freeconfig(lconfig);
		lirc_deinit();
		_exit(0);
	}

	act.sa_handler=sig_term;
	sigemptyset(&act.sa_mask);
	act.sa_flags=0;           /* we need EINTR */
	sigaction(SIGTERM,&act,NULL);
	
	while (1) {
		if ((nread = read(ptym, buf, BUFFSIZE)) <= 0)
			break;
		if (write(STDOUT_FILENO, buf, nread) != nread)
			die("writen error to stdout");
	}
	if (!sigcaught)
		kill(child, SIGTERM);
	lirc_freeconfig(lconfig);
	lirc_deinit();
	return;
}

static struct termios save_termios;
static int ttysavefd = -1;
static enum {
	RESET, RAW, CBREAK
} ttystate = RESET;

int tty_raw(int fd)
{
	struct termios buf;

	if (tcgetattr(fd, &save_termios) < 0)
		return (-1);

	buf = save_termios;
	buf.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	buf.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	buf.c_cflag &= ~(CSIZE | PARENB);
	buf.c_cflag |= CS8;
	buf.c_oflag &= ~(OPOST);
	buf.c_cc[VMIN] = 1;
	buf.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSAFLUSH, &buf) < 0)
		return (-1);
	ttystate = RAW;
	ttysavefd = fd;
	return (0);
}

int tty_reset(int fd)
{
	if (ttystate != CBREAK && ttystate != RAW)
		return (0);
	if (tcsetattr(fd, TCSAFLUSH, &save_termios) < 0)
		return (-1);
	ttystate = RESET;
	return (0);
}

void tty_atexit(void)
{
	if (ttysavefd >= 0)
		tty_reset(ttysavefd);
}

/* Open the next free pty */

int pty_open(char *pty_name)
{
	char *ptr1, *ptr2;
	int fd;

	strcpy(pty_name, "/dev/ptyp0");
	for (ptr1 = "pqrstuvwxyzabcde"; *ptr1; ptr1++) {
		pty_name[8] = *ptr1;
		for (ptr2 = "0123456789abcdef"; *ptr2; ptr2++) {
			pty_name[9] = *ptr2;

			if ((fd = open(pty_name, O_RDWR)) >= 0) {
				pty_name[5] = 't';
				return (fd);
			} else if (errno == ENOENT)
				return (-1);
		}
	}
	return (-1);
}

int tty_open(int fdm, char *tty_name)
{
	struct group *grptr;
	int gid, fds;

	if ((grptr = getgrnam("tty")) != NULL)
		gid = grptr->gr_gid;
	else
		gid = -1;

	/*
	chown(tty_name, getuid(), gid);
	chmod(tty_name, S_IRUSR | S_IWUSR | S_IWGRP);
	*/

	if ((fds = open(tty_name, O_RDWR)) < 0) {
		close(fdm);
		return (-1);
	}
	return (fds);
}

pid_t pty_fork(int *ptrfdm, char *slave_name,
			   struct termios * slave_termios,
			   struct winsize * slave_winsize)
{
	int fdm, fds;
	pid_t pid;
	char pts_name[20];

	if ((fdm = pty_open(pts_name)) < 0)
		die("can't open pty %s\n",pts_name);
	if (slave_name)
		strcpy(slave_name, pts_name);

	if ((pid = fork()) < 0)
		die("fork error\n");
	if (!pid) {
		if (setsid() < 0)
			die("setsid error");
		if ((fds = tty_open(fdm, pts_name)) < 0)
			die("can't open slave pty %s\n",pts_name);
		close(fdm);

		if (slave_termios) {
			if (tcsetattr(fds, TCSANOW, slave_termios) < 0)
				die("tcsetattr error on slave pty");
		}
		if (slave_winsize) {
			if (ioctl(fds, TIOCSWINSZ, slave_winsize) < 0)
				die("TIOCSWINSZ error on slave pty");
		}
		if (dup2(fds, STDIN_FILENO) != STDIN_FILENO)
			die("dup2 error to stdin");
		if (dup2(fds, STDOUT_FILENO) != STDOUT_FILENO)
			die("dup2 error to stdout");
		if (dup2(fds, STDERR_FILENO) != STDERR_FILENO)
			die("dup2 error to stderr");
		if (fds > STDERR_FILENO)
			close(fds);
		return (0);
	}
	*ptrfdm = fdm;
	return (pid);
}

static void set_noecho(int fd)
{
	struct termios stermios;

	if (tcgetattr(fd, &stermios) < 0)
		die("tcgetattr error");
	stermios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL);
	stermios.c_oflag &= ~(ONLCR);
	if (tcsetattr(fd, TCSANOW, &stermios) < 0)
		die("tcsetattr error");
}


int main(int argc, char *argv[])
{
	int fdm, c, ignoreeof, interactive, noecho, verbose;
	pid_t pid;
	char *config, slave_name[20];
	struct termios orig_termios;
	struct winsize size;
	char *sname = LIRCD;
	int flags;

	progname=argv[0];

	interactive = isatty(STDIN_FILENO);
	ignoreeof = 0;
	noecho = 0;
	verbose = 0;
	config = NULL;

	while ((c = getopt(argc, argv, "s:einv")) != EOF) {
		switch (c) {
		case 's':
			sname = optarg;
			break;

		case 'e':
			noecho = 1;
			break;

		case 'i':
			ignoreeof = 1;
			break;

		case 'n':
			interactive = 0;
			break;

		case 'v':
			verbose = 1;
			break;

		case '?':
			die("unrecognized option: -%c\n", optopt);
		}
	}
	if (optind + 1 >= argc)
		die("usage: irpty [ -s server -einv ] cfg program [ arg ... ]\n");

	config = argv[optind++];

	if((lsock=lirc_init("irpty",1))==-1) exit(EXIT_FAILURE);
	flags=fcntl(lsock,F_GETFL,0);
	if(flags!=-1)
	{
		fcntl(lsock,F_SETFL,flags|FASYNC|O_NONBLOCK);
	}

	if(lirc_readconfig(config,&lconfig,NULL)!=0) exit(EXIT_FAILURE);

	if (interactive) {
		if (tcgetattr(STDIN_FILENO, &orig_termios) < 0)
			die("tcgetattr error on stdin\n");
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, (char *) &size) < 0)
			die("TIOCGWINSZ error\n");
		pid = pty_fork(&fdm, slave_name, &orig_termios, &size);
	} else
		pid = pty_fork(&fdm, slave_name, NULL, NULL);

	if (pid < 0)
		die("fork error\n");
	else if (!pid) {			/* child */
		if (noecho)
			set_noecho(STDIN_FILENO);	/* stdin is slave pty */
		if (execvp(argv[optind], &argv[optind]) < 0)
			die("can't execute: %s\n", argv[optind]);
	}
	if (verbose) {
		fprintf(stderr, "slave name = %s\n", slave_name);
		if (config)
			fprintf(stderr, "config file = %s\n", config);
	}
	if (interactive) {
		if (tty_raw(STDIN_FILENO) < 0)	/* user's tty to raw mode */
			die("tty_raw error");
		if (atexit(tty_atexit) < 0)		/* reset user's tty on exit */
			die("atexit error");
	}
	copy_loop(fdm, ignoreeof);

	exit(0);
}

