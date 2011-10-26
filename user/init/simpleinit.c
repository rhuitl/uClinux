/* simpleinit.c - poe@daimi.aau.dk */
/* Version 1.21 */

/* gerg@snapgear.com -- modified for direct console support DEC/1999 */
/* davidm@snapgear.com -- modified for init.conf SEP/2004 */
/* toby@snapgear.com -- allow the array of commands to grow as needed OCT/2004 */
/* davidm@snapgear.com -- use dynamically allocated tables APR/2005 */

#define _GNU_SOURCE	/* For crypt() and termios defines */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/version.h>
#include <utmp.h>
#include <errno.h>
#include <time.h>
#include <termios.h>
#ifdef SHADOW_PWD
#include <shadow.h>
#endif

#include <config/autoconf.h>

#if __GNU_LIBRARY__ > 5
#include <sys/reboot.h>
#endif

#include "pathnames.h"

#define BUF_SIZ 100	/* max size of a line in inittab */
#define NUMCMD 30	/* step size when realloc more space for the commands */
#define NUMTOK 20	/* max number of tokens in inittab command */

/* Threshold time for detecting "fast" spawning processes */
static int testtime  = 90;
/* Number of rapid respawns that counts as too fast */
static int maxspawn  = 5;
/* Maximum delay between runs */
static int maxdelay  = 595;
/* Time between successive runs of a process */
static int delaytime = 5;

#define MAXTRIES 3	/* number of tries allowed when giving the password */

#define RUN_RC		/* Use a console if possible */

#ifndef CTRL
#define CTRL(X) ((X)&037)
#endif

#ifdef INCLUDE_TIMEZONE
char tzone[BUF_SIZ];
#endif
/* #define DEBUGGING */

/* Define this if you want init to ignore the termcap field in inittab for
   console ttys. */
/* #define SPECIAL_CONSOLE_TERM */

struct initline {
	pid_t	pid;
	time_t	lastrun;
	time_t	nextrun;
	char	**toks;
	short	delay;
	char	tty[10];
	char	termcap[30];
	char	*line;
	char	*fullline;
	unsigned char xcnt;
};

struct initline *inittab;
/* How many struct initline's will fit in the memory pointed to by inittab */
int inittab_size = 0; 
int numcmd;
int stopped = 0;	/* are we stopped */
int reload = 0;	/* are we stopped */
int run_sigint_processing = 0;

extern void spawn(int);
extern void hup_handler();
extern void reload_inittab();
extern void read_inittab(void);
static int  read_initfile(const char *);
extern void tstp_handler();
extern void int_handler();
extern void sigint_processing();
extern void cont_handler();
extern void set_tz(void);
extern void write_wtmp(void);
extern void make_ascii_tty(void);
extern void make_console(const char *);
extern int boot_single(int singlearg, int argc, char *argv[]);
#ifdef CONFIG_USER_INIT_CONF
extern void load_init_conf(void);
#endif

/* Keep track of console device, if any... */
#if LINUX_VERSION_CODE < 0x020100
char	*console_device = NULL;
int	console_baud = -1;
#else
int have_console = 0;
#endif


static void err(const char *s)
{
	struct iovec output[2];
#if LINUX_VERSION_CODE < 0x020100
	int fd;
#endif
	output[0].iov_base = "init: ";
	output[0].iov_len = 6;
	output[1].iov_base = (void *)s;
	output[1].iov_len = strlen(s);
#if LINUX_VERSION_CODE < 0x020100	
	if (console_device == NULL) return;
	if((fd = open(console_device, O_WRONLY)) < 0) return;
	writev(fd, output, 2);
	close(fd);
#else
	if (have_console)
		writev(1, output, 2);
#endif
}

void
add_tok(struct initline *p, char *tok)
{
	int i;
	for (i = 0; p->toks && p->toks[i]; i++)
		;

	/* allocate space for new entry and terminating NULL */
	p->toks = (char **) realloc(p->toks, (i + 2) * sizeof(char *));
	if (!p->toks) {
		err("malloc failed\n");
		_exit(1);
	}
	p->toks[i++] = tok;
	p->toks[i] = NULL;
}

static void enter_single(void)
{
	pid_t pid;
	char *av[2];

    err("Booting to single user mode\n");
    av[0] = _PATH_BSHELL;
    av[1] = NULL;
    if((pid = vfork()) == 0) {
    extern char **environ;
	/* the child */
	execve(_PATH_BSHELL, av, environ);
	err("exec of single user shell failed\n");
	_exit(0);
    } else if(pid > 0) {
    int i;
	while(wait(&i) != pid) /* nothing */;
    } else if(pid < 0) {
	err("fork of single user shell failed\n");
    }
    unlink(_PATH_SINGLE);
}


#if LINUX_VERSION_CODE < 0x020100
static void
set_console_baud(int baud)
{
	switch (baud) {
	case 50:     console_baud = B50; break;
	case 75:     console_baud = B75; break;
	case 110:    console_baud = B110; break;
	case 134:    console_baud = B134; break;
	case 150:    console_baud = B150; break;
	case 200:    console_baud = B200; break;
	case 300:    console_baud = B300; break;
	case 600:    console_baud = B600; break;
	case 1200:   console_baud = B1200; break;
	case 1800:   console_baud = B1800; break;
	case 2400:   console_baud = B2400; break;
	case 4800:   console_baud = B4800; break;
	default:
	case 9600:   console_baud = B9600; break;
	case 19200:  console_baud = B19200; break;
	case 38400:  console_baud = B38400; break;
	case 57600:  console_baud = B57600; break;
	case 115200: console_baud = B115200; break;
	case 230400: console_baud = B230400; break;
	case 460800: console_baud = B460800; break;
	}
}
#endif

static int do_command(const char *path, const char *filename, int dowait)
{
	pid_t pid, wpid;
	int stat, st;
	
	if((pid = vfork()) == 0) {
		/* the child */
		char *argv[3];
#ifdef INCLUDE_TIMEZONE
		char tz[BUF_SIZ];
#endif
		char *env[3];

		/* Use /dev/null for stdin */
		close(0);
		open("/dev/null", O_RDONLY);

		argv[0] = (char *)path;
		argv[1] = (char *)filename;
		argv[2] = NULL;

		env[0] = "PATH=/bin:/usr/bin:/etc:/sbin:/usr/sbin";
#ifdef INCLUDE_TIMEZONE
		strcpy(tz, "TZ=");
		strcat(tz, tzone);
		env[1] = tz;
		env[2] = NULL;
#else
		env[1] = NULL;
#endif

		execve(path, argv, env);

		err("exec rc failed\n");
		_exit(2);
	} else if(pid > 0) {
		if (!dowait)
			stat = 0;
		else {
			/* parent, wait till rc process dies before spawning */
			while ((wpid = wait(&stat)) != pid)
				if (wpid == -1 && errno == ECHILD) { /* see wait(2) manpage */
					stat = 0;
					break;
				}
		}
	} else if(pid < 0) {
		err("fork of rc shell failed\n");
		stat = -1;
	}
	st = WEXITSTATUS(stat);
	return st;
}

/*
 * run /etc/rc. The environment is passed to the script, so the RC environment
 * variable can be used to decide what to do. RC may be set from LILO.
 */
static int do_rc(void)
{
	int rc;

	rc = do_command(_PATH_BSHELL, _PATH_RC, 1);
	if (rc)
		return(rc);
#ifdef CONFIG_USER_INIT_RUN_FIREWALL
	rc = do_command(_PATH_FIREWALL, "-i", 1);
	if (rc)
		err(_PATH_FIREWALL " failed!");
#endif
#ifdef CONFIG_USER_FLATFSD_FLATFSD
	rc = do_command(_PATH_BSHELL, _PATH_CONFIGRC, 1);
	if (rc)
		err(_PATH_CONFIGRC " failed!");
#endif
#ifdef CONFIG_USER_INIT_RUN_FIREWALL
	rc = do_command(_PATH_FIREWALL, NULL, 0);
	if (rc)
		err(_PATH_FIREWALL " failed!");
#endif
#ifdef INCLUDE_TIMEZONE
	/* We read the timezone file here, because the flat file system
	 * has probably been created by now.
	 */
	set_tz();
#endif
	return(0);
}

void respawn_children(int signo) {
	int i, delta = -1;
	time_t now;
	alarm(0);
	if ((now = time(NULL)) == 0) now = 1;
	for(i = 0; i < numcmd; i++) {
		if(inittab[i].pid < 0) {	/* Start jobs */
			if(stopped)
				inittab[i].pid = -1;
			/*
			** Do not spawn child from signal handler !
			** SIGALRM would be blocked for the child
			*/
			else if (signo == 0)
				spawn(i);
		}
		/* Check for naughty jobs */
		if (inittab[i].nextrun > now) {
		int d;
			d = inittab[i].nextrun - now;
			if (delta < 0 || d < delta)
				delta = d;
		}
	}
	if (delta > 0) {
		alarm(delta);
	}
}

int main(int argc, char *argv[])
{
	int 	i;
	struct sigaction sa;

	/*
	 * setup all the signal handlers here
	 */

	memset(&sa, 0, sizeof(sa));
	/* sa.sa_flags = SA_RESETHAND we want to keep the handlers armed */

	sa.sa_handler = tstp_handler;
	sigaction(SIGTSTP, &sa, NULL);

	sa.sa_handler = cont_handler;
	sigaction(SIGCONT, &sa, NULL);

	sa.sa_handler = int_handler;
	sigaction(SIGINT, &sa, NULL);

	sa.sa_handler = respawn_children;
	sigaction(SIGALRM, &sa, NULL);

	sa.sa_handler = hup_handler;
	sigaction(SIGHUP, &sa, NULL);

#if defined(CONSOLE_BAUD_RATE) && LINUX_VERSION_CODE < 0x020100
	set_console_baud(CONSOLE_BAUD_RATE);
#endif

	/* 
	 * start up in single user mode if /etc/singleboot exists or if
	 * argv[1] is "single".
	 */
	if(boot_single(0, argc, argv)) enter_single();

#ifdef RUN_RC
	/* Register console if defined by boot */
#if LINUX_VERSION_CODE < 0x020100
	if ((console_device = getenv("CONSOLE"))) {
	char	*sp;
		unsetenv("CONSOLE");
		if ((sp = strchr(console_device, ','))) {
			*sp++ = 0;
			set_console_baud(atoi(sp));
		}
	}

	make_ascii_tty();
#else
{
	struct stat st;

	if (isatty(1)) {
		have_console = 1;
		make_ascii_tty();
	} else if (fstat(1, &st) == -1 && errno == EBADF) {
		/* No stdout, so send everything to /dev/null */
		close(0); close(1); close(2);
		open("/dev/null", O_RDWR);
		dup(0);
		dup(0);
	}
}
#endif

	/*If we get a SIGTSTP before multi-user mode, do nothing*/
	while(stopped)	
		pause();
	if(do_rc() != 0 && boot_single(1, argc, argv) && !stopped)
		enter_single();
	while(stopped)	/*Also if /etc/rc fails & we get SIGTSTP*/
		pause();
#endif

	/* initialize the array of commands */
	inittab = (struct initline *)malloc(NUMCMD * sizeof(struct initline));
	inittab_size = NUMCMD;

	if (!inittab) {
		/* failure case - what do you do if init fails? */
		err("malloc failed");
		_exit(1);
	}

	write_wtmp();	/* write boottime record */
	read_inittab();

#ifdef DEBUGGING
	for(i = 0; i < numcmd; i++) {
		char **p = inittab[i].toks;
		printf("toks= %s %s %s %s\n",p[0], p[1], p[2], p[3]);
		printf("tty= %s\n", inittab[i].tty);
		printf("termcap= %s\n", inittab[i].termcap);
	}
	/*exit(0);*/
#endif

#if LINUX_VERSION_CODE < 0x020100
	for(i = 0; i < getdtablesize(); i++) close(i);
#else
	/* Always leave 0, 1, and 2 connected (to /dev/null) for the child process */
	for(i = 3; i < getdtablesize(); i++) close(i);
#endif

	for (;;) {
		pid_t	pid;
		int	vec;

		if (run_sigint_processing) {
			run_sigint_processing = 0;
			sigint_processing();
		}

		respawn_children(0);

		if (reload) {
			reload = 0;
			reload_inittab();
			continue; /* process all reloads before waiting */
		}

		pid = wait(&vec);
		alarm(0);

		/* clear utmp entry, and append to wtmp if possible */
#if 0		/* DAVIDM */
		{
		    struct utmp *ut;
		    int ut_fd;

		    utmpname(_PATH_UTMP);
		    setutent();
		    while((ut = getutent())) {
			if(ut->ut_pid == pid) {
			    time(&ut->ut_time);
			    bzero(&ut->ut_user, UT_NAMESIZE);
			    bzero(&ut->ut_host, sizeof(ut->ut_host));
			    ut->ut_type = DEAD_PROCESS;
			    ut->ut_pid = 0;
			    ut->ut_addr = 0;
			    endutent();
			    pututline(ut);
			    if((ut_fd = open(_PATH_WTMP, O_APPEND|O_WRONLY)) >= 0) {
				flock(ut_fd, LOCK_EX|LOCK_NB);
				write(ut_fd, (const void *)ut, sizeof(struct utmp));
				flock(ut_fd, LOCK_UN|LOCK_NB);
				close(ut_fd);
			    }
			    break;
			}
		    }
		    endutent();
		}
#endif

		for(i = 0; i < numcmd; i++) {
			if(pid == inittab[i].pid) {
				inittab[i].pid = -1;
			}
		}
	}
}	


/*
 * return true if we should boot up in singleuser mode. If argv[i] is 
 * "single" or the file /etc/singleboot exists, then singleuser mode should
 * be entered. If /etc/securesingle exists ask for root password first.
 */
int boot_single(int singlearg, int argc, char *argv[])
{
	char *pass, *rootpass = NULL;
	struct passwd *pwd;
	int i;

	for(i = 1; i < argc; i++) {
	    if(argv[i] && !strcmp(argv[i], "single")) singlearg = 1;
	}

	if(access(_PATH_SINGLE, 04) == 0 || singlearg) {
		if(access(_PATH_SECURE, 04) == 0) {
			if((pwd = getpwnam("root")) || (pwd = getpwuid(0)))
			  rootpass = pwd->pw_passwd;
			else
			  return 1; /* a bad /etc/passwd should not lock out */

			for(i = 0; i < MAXTRIES; i++) {
				pass = getpass("Password: ");
				if(pass == NULL) continue;
				
				if(!strcmp(crypt(pass, rootpass), rootpass)) {
					return 1;
				}

				puts("\nWrong password.\n");
			}
		} else return 1;
	}
	return 0;
}

void spawn(int i)
{
	pid_t pid;
	int j;
	time_t t;
	struct initline *it;
	char buf[150];
	
	it = inittab + i;

	t = time(NULL);
	/* Check for held process */
	if ((unsigned long)(it->nextrun - t - 1) < maxdelay)
		return;
	if (it->lastrun + testtime > t) {	/* Respawning quickly */
		if (it->xcnt < 0xff)
			it->xcnt++;
	} else {				/* Normal respawning */
		it->xcnt = 0;
		it->lastrun = t;
		it->delay = delaytime;
	}
	if (it->xcnt >= maxspawn) {		/* Too many too quickly */
		strcpy(buf, it->toks[0]);
		strcat(buf, " respawning too fast\n");
		err(buf);
		it->pid = -1;
		if (it->delay >= maxdelay)
			it->delay = maxdelay;
		else if (it->delay < delaytime)
			it->delay = delaytime;
		else if((it->delay *= 2) > maxdelay)
			it->delay = maxdelay;
		it->nextrun = t + it->delay;
		/* Fiddle with the tracking vars to ensure that only
		 * one attempt is made to run this next time around.
		 */
		it->lastrun = it->nextrun;
		it->xcnt -= 2;
		return;
	}
	it->nextrun = t + delaytime;
	
	if((pid = vfork()) < 0) {
		it->pid = -1;
		err("fork failed\n");
		return;
	}
	if(pid) {
		/* this is the parent */
		it->pid = pid;
		return;
	} else {
		/* this is the child */
		char term[40];
		char *prog;
#ifdef INCLUDE_TIMEZONE
		char tz[BUF_SIZ];
#endif
		char *env[4];
		
		setsid();

		/* Close everything other than 0, 1 and 2 */
		for(j = 3; j < getdtablesize(); j++) {
			close(j);
		}
		/* Now set up 0, 1 and 2 */
		make_console(it->tty);

		strcpy(term, "TERM=");
		strcat(term, it->termcap);
		env[0] = term;
		env[1] = "PATH=/bin:/usr/bin:/etc:/sbin:/usr/sbin";
#ifdef INCLUDE_TIMEZONE
		strcpy(tz, "TZ=");
		strcat(tz, tzone);
		env[2] = tz;
		env[3] = NULL;
#else
		env[2] = NULL;
#endif

		prog = it->toks[0];
		if (*prog == '-' && *(prog+1))
			prog++;
		execve(prog, it->toks, env);
		strcpy(buf, it->toks[0]);
		strcat(buf, " exec failed\n");
		err(buf);
		_exit(1);
	}
}

static void init_itab(struct initline *p) {
	bzero(p, sizeof(struct initline));
	p->pid = -1;
	p->nextrun = time(NULL);
}

static void clear_itab(struct initline *p) {
	if (p->line)
		free(p->line);
	if (p->fullline)
		free(p->fullline);
	if (p->toks)
		free(p->toks);
	init_itab(p);
}

void read_inittab(void)
{
	int i;

	/*
	 * free any old data and start again
	 */
	for (i = 0; i < numcmd; i++)
		clear_itab(&inittab[i]);
	numcmd = 0;

	/* Fake an inittab entry if boot console defined */
#ifdef CONFIG_USER_INIT_CONSOLE_SH
#if LINUX_VERSION_CODE < 0x020100
	if (console_device && strcmp(console_device, "/dev/null"))
#else
	if (have_console)
#endif
	{
	struct initline *p;
		p = inittab + numcmd++;
		init_itab(p);
		p->fullline = strdup("console");
		strcpy(p->tty, "console");
		strcpy(p->termcap, "linux");
		add_tok(p, "-/bin/sh");
	}
#endif

	i = 0;
	if (read_initfile(_PATH_INITTAB) == 0)
		i++;

#ifdef CONFIG_USER_FLATFSD_FLATFSD
	if (read_initfile(_PATH_CONFIGTAB) == 0)
		i++;
#endif

	if (i == 0) {
		err("Failed to open " _PATH_INITTAB
#ifdef CONFIG_USER_FLATFSD_FLATFSD
				" or " _PATH_CONFIGTAB
#endif
				"."
				);
	}

#ifdef CONFIG_USER_INIT_CONF
	load_init_conf();
#endif

	/* if needed, shrink the array using realloc -
	 * must be done here so that we include the results of all init files
	 * when calculating number of commands */
	if ((numcmd + 2) < (inittab_size - NUMCMD)) {
		/* round up from numcmd to the nearest multiple of NUMCMD */
		inittab_size = ((numcmd + 2) / NUMCMD + 1) * NUMCMD;
		inittab = realloc(inittab, inittab_size * sizeof(struct initline));
		if (!inittab) {
			/* failure case - what do you do if init fails? */
			err("malloc failed");
			_exit(1);
		}
	}

	if (numcmd == 0)
		_exit(1);
}

static int
read_initfile(const char *initfile)
{
	struct initline *p;
	FILE *f;
	char *buf = NULL;
	size_t buf_len = 0;
	int i,j,k;
	char *ptr, *getty;
#ifdef SPECIAL_CONSOLE_TERM
	char tty[50];
	struct stat stb;
	char *termenv;

	termenv = getenv("TERM");	/* set by kernel */
#endif

	i = numcmd;

	if (!(f = fopen(initfile, "r")))
		return 1;

	while(!feof(f)) {
		if (i+2 == inittab_size) {
			/* need to realloc inittab */
			inittab_size += NUMCMD;
			inittab = realloc(inittab, inittab_size * sizeof(struct initline));
			if (!inittab) {
				/* failure case - what do you do if init fails? */
				err("malloc failed");
				_exit(1);
			}
		}
		if (getline(&buf, &buf_len, f) == -1) break;

		for(k = 0; k < buf_len && buf[k]; k++) {
			if(buf[k] == '#') { 
				buf[k] = '\0'; break; 
			}
		}

		if(buf[0] == '\0' || buf[0] == '\n') continue;

		p = inittab + i;
		init_itab(p);
		p->line = strdup(buf);
		p->fullline = strdup(buf);
		if (!p->line || !p->fullline) {
			err("Not memory to allocate inittab entry");
			clear_itab(p);
			continue;
		}
		ptr = strtok(p->line, ":");
		if (!ptr) {
			err("Missing TTY/ID field in inittab");
			clear_itab(p);
			continue;
		}
		strncpy(p->tty, ptr, 9);
		//p->tty[9] = '\0';
		ptr = strtok(NULL, ":");
		if (!ptr) {
			err("Missing TERMTYPE field in inittab");
			clear_itab(p);
			continue;
		}
		strncpy(p->termcap, ptr, 29);
		//p->termcap[29] = '\0';

		getty = strtok(NULL, " \t\n");
		if (!getty) {
			err("Missing PROCESS field in inittab");
			clear_itab(p);
			continue;
		}
		add_tok(p, getty);
		j = 1;
		while((ptr = strtok(NULL, " \t\n")))
			add_tok(p, ptr);

#ifdef SPECIAL_CONSOLE_TERM
		/* special-case termcap for the console ttys */
		strcpy(tty, "/dev/");
		strcat(tty, p->tty);
		if(!termenv || stat(tty, &stb) < 0) {
			err("no TERM or cannot stat tty\n");
		} else {
			/* is it a console tty? */
			if(major(stb.st_rdev) == 4 && minor(stb.st_rdev) < 64) {
				strncpy(p->termcap, termenv, 30);
				p->termcap[29] = 0;
			}
		}
#endif

		i++;
	}

	if (buf)
		free(buf);
	
	fclose(f);

	numcmd = i;
	return 0;
}

void hup_handler()
{
	reload = 1;
}

void reload_inittab()
{
	int i;
	int oldnum;
	char ** saveline = (char **) malloc(inittab_size * sizeof(char *));
	pid_t * savepid = (pid_t*) malloc(inittab_size * sizeof(pid_t));

	if (!saveline || !savepid) {
		/* another failure case - what DO you do if init fails */
		err("malloc failed");
		_exit(1);
	}

	for (i=0; i<numcmd; i++) {
		savepid[i] = inittab[i].pid;
		saveline[i] = strdup(inittab[i].fullline);
		if (!saveline[i]) {
			err("malloc failed");
			_exit(1);
		}
	}

	oldnum = numcmd;		
	read_inittab();

	/* See which ones still exist */
	for(i = 0; i < numcmd; i++) {
		int j;
		for(j = 0; j < oldnum; j++) {
			if(strcmp(saveline[j], inittab[i].fullline) == 0) {
				inittab[i].pid = savepid[j];
				savepid[j] = -1;
				break;
			}
		}
	}

	/* Kill off processes no longer needed and free memory */
	for(i = 0; i < oldnum; i++) {
		if (savepid[i] > 1)
			kill(savepid[i], SIGTERM);
		free(saveline[i]);
	}

	free(saveline);
	free(savepid);
}

void tstp_handler()
{
	stopped++;
}

void cont_handler()
{
	stopped = 0;
}

void int_handler()
{
	run_sigint_processing = 1;
}

void sigint_processing()
{
	/*
	 * After Linux 0.96b PL1, we get a SIGINT when
	 * the user presses Ctrl-Alt-Del...
	 */

	int pid;
	
	sync();
	sync();
	if((pid = vfork()) == 0) {
	char *av[2];
	extern char **environ;
		/* reboot properly... */
		av[0] = _PATH_REBOOT;
		av[1] = NULL;
		
		execve(_PATH_REBOOT, av, environ);
#if __GNU_LIBRARY__ > 5
		reboot(0x1234567);
#else
		reboot(0xfee1dead, 672274793, 0x1234567);
#endif
		_exit(2);
	} else if(pid < 0) {
		/* fork failed, try the hard way... */
#if __GNU_LIBRARY__ > 5
		reboot(0x1234567);
#else
		reboot(0xfee1dead, 672274793, 0x1234567);
#endif
	}
}

#ifdef INCLUDE_TIMEZONE
void set_tz(void)
{
	FILE *f;
	int len;

	if((f = fopen("/etc/config/TZ", "r")) == NULL &&
	   (f = fopen("/etc/TZ", "r")) == NULL)
		return;
	fgets(tzone, BUF_SIZ-2, f);
	fclose(f);
	if((len=strlen(tzone)) < 2)
		return;
	tzone[len-1] = 0; /* get rid of the '\n' */
	setenv("TZ", tzone, 0);
}
#endif

#ifdef CONFIG_USER_INIT_CONF
void load_init_conf(void)
{
	char line[BUF_SIZ];
	FILE *f;

	if ((f = fopen("/etc/config/init.conf", "r")) == NULL &&
			(f = fopen("/etc/init.conf", "r")) == NULL)
		return;
	while (fgets(line, sizeof(line) - 2, f)) {
		if (strncasecmp(line, "delaytime=", 10) == 0)
			delaytime = atoi(line + 10);
		if (strncasecmp(line, "maxdelay=", 9) == 0)
			maxdelay = atoi(line + 9);
		if (strncasecmp(line, "maxspawn=", 9) == 0)
			maxspawn = atoi(line + 9);
		if (strncasecmp(line, "testtime=", 9) == 0)
			testtime = atoi(line + 9);
	}
	fclose(f);
}
#endif

void write_wtmp(void)
{
#if 0
    int fd;
    struct utmp ut;
    
    bzero((char *)&ut, sizeof(ut));
    strcpy(ut.ut_line, "~");
    bzero(ut.ut_name, sizeof(ut.ut_name));
    time(&ut.ut_time);
    ut.ut_type = BOOT_TIME;
    
    if((fd = open(_PATH_WTMP, O_WRONLY|O_APPEND)) >= 0) {
	flock(fd, LOCK_EX|LOCK_NB); /* make sure init won't hang */
	write(fd, (char *)&ut, sizeof(ut));
	flock(fd, LOCK_UN|LOCK_NB);
	close(fd);
    }
#endif
}     

void make_ascii_tty(void)
{
	struct termios tty;
	const char *pt;

	if (tcgetattr(0, &tty) < 0)
		return;

	tty.c_iflag &= ~(INLCR|IGNCR|IUCLC);
	tty.c_iflag |= ICRNL;
	tty.c_oflag &= ~(OCRNL|OLCUC|ONOCR|ONLRET|OFILL);
	tty.c_oflag |= OPOST|ONLCR;
	tty.c_cflag |= CLOCAL;
	tty.c_lflag  = ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE;
#ifdef IEXTEN
	tty.c_lflag  |= IEXTEN;
#endif

#if LINUX_VERSION_CODE < 0x020100
	if (console_baud != -1)
		cfsetospeed(&tty, console_baud);
#endif

	tty.c_cc[VINTR]  = CTRL('C');
	tty.c_cc[VQUIT]  = CTRL('\\');
	tty.c_cc[VERASE] = CTRL('H'); /*127*/
	tty.c_cc[VKILL]  = CTRL('U'); /*Changed from non-standard ^X*/
	tty.c_cc[VEOF]   = CTRL('D');
	tty.c_cc[VTIME]  = 0;
	tty.c_cc[VMIN]   = 1;
	tty.c_cc[VSTART] = CTRL('Q');
	tty.c_cc[VSTOP]  = CTRL('S');
	tty.c_cc[VSUSP]  = CTRL('Z');
#ifdef VWERASE
	tty.c_cc[VWERASE]  = CTRL('W');
#endif
	/* Pick up simple environment setting of VERASE.
	 * Useful for setting on kernel command line.
	 * e.g. TTYERASE=^?
	 */
	pt = getenv("TTYERASE");
	if (pt && pt[0] == '^' && pt[1]) {
		tty.c_cc[VERASE] = (pt[1] == '?') ? 127 : CTRL(pt[1]);
	}

	tcsetattr(0, TCSANOW, &tty);
}

void make_console(const char *tty)
{
	char devname[32];

	close(0); close(1); close(2);

	if (tty && *tty) {
#if LINUX_VERSION_CODE < 0x020100
	    /*
	     *	until we get proper console support under 2.0
	     */
	    if (strcmp(tty, "console") == 0) {
		    strcpy(devname, console_device);
	    }
	    else
#endif
	    {
		    strcpy(devname, "/dev/");
		    strcat(devname, tty);
	    }

	    /* Try to open the specified console */
	    if (open(devname, O_RDWR|O_NONBLOCK) >= 0) {
		fcntl(0, F_SETFL, 0);
		dup(0); 
		dup(0);
		make_ascii_tty();
		ioctl(0, TIOCSCTTY, (char*)0);
		return;
	    }
	}

	/* No go, so send to /dev/null */
	open("/dev/null", O_RDWR|O_NONBLOCK);
	dup(0);
	dup(0);
}
