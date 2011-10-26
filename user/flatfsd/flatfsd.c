/*****************************************************************************/

/*
 *	flatfsd.c -- Flat file-system daemon.
 *
 *	(C) Copyright 1999-2006, Greg Ungerer <gerg@snapgear.com>
 *	(C) Copyright 2000-2001, Lineo Inc. (www.lineo.com)
 *	(C) Copyright 2001-2002, SnapGear (www.snapgear.com)
 *	(C) Copyright 2004-2006, CyberGuard (www.cyberguard.com)
 *	(C) Copyright 2002-2005, David McCullough <davidm@snapgear.com>
 */

/*****************************************************************************/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <linux/autoconf.h>
#include <config/autoconf.h>
#if defined(CONFIG_LEDMAN)
#include <linux/ledman.h>
#endif

#include "flatfs.h"
#include "reboot.h"

/*****************************************************************************/

/*
 * By default create version 4 flat fs files (compressed/duplicated).
 * Allow it to be overriden on the command line with args though.
 */
static int fsver = 4;

/*****************************************************************************/

/*
 * Temporary marker file.
 */
#define	IGNORE_FLASH_WRITE_FILE	"/tmp/.flatfsd_ignore_write"

/*****************************************************************************/

#define ACTION_NONE		0
#define ACTION_EXIT		(1<<1)
#define ACTION_READ		(1<<2)
#define ACTION_WRITE		(1<<3)
#define ACTION_RESET		(1<<4)
#define ACTION_REBOOT		(1<<5)
#define ACTION_HALT		(1<<6)
#define ACTION_BUTTON		(1<<7)
#define ACTION_DIRTY		(1<<8)
#define ACTION_REBOOT_NOW	(1<<9)
#define	ACTION_POWEROFF		(1<<10)

static int action = 0;
static time_t dirty;

/*****************************************************************************/

/*
 * The code to do Reset/Erase button menus.
 */
static int current_cmd = 0;

#define MAX_LED_PATTERN 4
#define	ACTION_TIMEOUT 5		/* timeout before action in seconds */

#ifndef CONFIG_LEDMAN
#define LEDMAN_RESET 0
#endif

static struct {
	unsigned int	action;
	unsigned long	led;
	unsigned long	timeout;
} cmd_list[] = {
	{ ACTION_NONE, 0, 0 },
	{ ACTION_NONE, 0, 2 },
	{ ACTION_RESET, LEDMAN_RESET, 0 },
};
#define cmd_num (sizeof(cmd_list)/sizeof(cmd_list[0]))

/*****************************************************************************/

static int recv_hup;		/* SIGHUP = reboot device */
static int recv_usr1;		/* SIGUSR1 = write config to flash */
static int recv_usr2;		/* SIGUSR2 = erase flash and reboot */
static int recv_pwr;		/* SIGPWR = halt device */
static int recv_chld;		/* SIGCHLD */
static int stopped;
static int exit_flatfsd;	/* SIGINT, SIGTERM, SIGQUIT */
static int nowrite;
static char *configdir = DSTDIR;
static char *filefs;

static void sigusr1(int signr)
{
	recv_usr1 = 1;
}

static void sigusr2(int signr)
{
	recv_usr2 = 1;
}

static void sighup(int signr)
{
	recv_hup = 1;
}

static void sigpwr(int signr)
{
	recv_pwr = 1;
}

static void sigchld(int signr)
{
	recv_chld = 1;
}

static void sigcont(int signr)
{
	stopped = 0;
}

static void sigexit(int signr)
{
	exit_flatfsd = 1;
}

/*****************************************************************************/

static char *get_caller(void)
{
	char procname[64];
	char cmdline[64];
	pid_t pp;
	FILE *fp;
	char *arg;

	procname[0] = '\0';

	pp = getppid();
	snprintf(cmdline, sizeof(cmdline), "/proc/%d/cmdline", pp);
	fp = fopen(cmdline, "r");
	if (fp) {
		fgets(procname, sizeof(procname), fp);
		fclose(fp);
	}

	if (procname[0] == '\0')
		strcpy(procname, "???");

	asprintf(&arg, "%d: %s", (int)pp, procname);
	return arg;
}

static void log_caller(const char *cmd)
{
	char *arg;

	arg = get_caller();
	vlogd(1, cmd, arg);
	free(arg);
}

/*****************************************************************************/

#define PATH_FLATFSD_SOCKET "/var/tmp/flatfsd.cmd"

static int createsocket(void)
{
	struct sockaddr_un addr;
	int sockfd;

	sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		syslog(LOG_ERR, "Failed to open socket: %m");
		exit(1);
	}

	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0)
		syslog(LOG_ERR, "Failed to set socket FD_CLOEXEC: %m");

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, PATH_FLATFSD_SOCKET);
	unlink(addr.sun_path);
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Failed to bind socket: %m");
		exit(1);
	}

	return sockfd;
}

static void readsocket(int sockfd)
{
	struct sockaddr_un addr;
	socklen_t addrlen = sizeof(addr);
	char buf[128];
	int len;
	char *caller;

	len = recvfrom(sockfd, buf, sizeof(buf) - 1, 0,
			(struct sockaddr *)&addr, &addrlen);
	if (len < 0) {
		syslog(LOG_ERR, "Failed to recv from socket: %m");
		return;
	}
	if (len == 0 || len >= sizeof(buf)) {
		syslog(LOG_ERR, "Failed to recv from socket, bad length %d",
				len);
		return;
	}

	caller = strchr(buf, '\t');
	if (caller)
		*(caller++) = '\0';

	buf[len] = 0;
	if (strcmp(buf, "exit") == 0) {
		action |= ACTION_EXIT;
	}
	else if (strcmp(buf, "stop") == 0) {
		stopped = 1;
	}
	else if (strcmp(buf, "cont") == 0) {
		stopped = 0;
	}
	else if (stopped) {
		/* Ignore any other commands while stopped */
	}
	else if (strcmp(buf, "write") == 0) {
		vlogd(1, "flatfsd-s", caller);
		action |= ACTION_WRITE;
	}
	else if (strcmp(buf, "dirty") == 0) {
		if (!dirty) {
			vlogd(1, "flatfsd-dirty", caller);
			action |= ACTION_DIRTY;
		}
	}
	else if (strcmp(buf, "reset") == 0) {
		vlogd(1, "flatfsd-i", caller);
		action |= ACTION_RESET;
	}
	else if (strcmp(buf, "reboot") == 0) {
		vlogd(1, "flatfsd-b", caller);
		action |= ACTION_REBOOT;
	}
	else if (strcmp(buf, "halt") == 0) {
		vlogd(1, "flatfsd-h", caller);
		action |= ACTION_HALT;
	}
	else if (strcmp(buf, "poweroff") == 0) {
		vlogd(1, "flatfsd-p", caller);
		action |= ACTION_POWEROFF;
	}
	else {
		syslog(LOG_ERR, "Unknown command: %s", buf);
	}
}

static int writesocket(const char *cmd)
{
	struct sockaddr_un addr;
	int sockfd;
	int len;
	char *caller;
	char *buf;

	sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		syslog(LOG_ERR, "Failed to open socket: %m");
		return 1;
	}

	caller = get_caller();
	len = asprintf(&buf, "%s\t%s", cmd, caller);
	free(caller);
	if (len < 0) {
		len = strlen(cmd);
		buf = NULL;
	}

	if (len > 100)
		len = 100;

	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, PATH_FLATFSD_SOCKET);
	if (sendto(sockfd, buf ?: cmd, len, 0,
			(struct sockaddr *)&addr, sizeof(addr)) != len) {
		close(sockfd);
		syslog(LOG_ERR, "Failed to write socket: %m");
		return 1;
	}

	free(buf);
	close(sockfd);
	return 0;
}

/*****************************************************************************/

static void check_config(void)
{
#ifdef USING_FLASH_FILESYSTEM
	exit(0);
#else
	execlp("flatfs", "flatfs", "-c", NULL);
	exit(1);
#endif
}

/*****************************************************************************/

/*
 * Save the filesystem to flash in flat format for retrieval later.
 */

static pid_t save_config_to_flash(void)
{
#ifdef USING_FLASH_FILESYSTEM
	return 0;
#else
	struct stat st_buf;
	char fsveropt[16];
	char *argv[16];
	pid_t pid;
	int i = 0;

	if (nowrite)
		return 0;

	if (stat(IGNORE_FLASH_WRITE_FILE, &st_buf) >= 0) {
		syslog(LOG_INFO, "Not writing to flash because %s exists",
			IGNORE_FLASH_WRITE_FILE);
		return 0;
	}

	snprintf(fsveropt, sizeof(fsveropt), "-%d", fsver);
	argv[i++] = "flatfs";
	argv[i++] = "-s";
	argv[i++] = fsveropt;
	argv[i++] = "-d";
	argv[i++] = configdir;
	if (filefs) {
		argv[i++] = "-f";
		argv[i++] = filefs;
	}
	argv[i++] = (char *) NULL;

	pid = vfork();
	if (pid == 0) {
		execvp(argv[0], argv);
		_exit(1);
	}
	return pid;
#endif
}

/*****************************************************************************/

/*
 * Read the filesystem from flash in flat format
 */

static int read_config_from_flash(void)
{
#ifdef HAS_RTC
	time_t bst = BUILD_START_UNIX;

	if (time(NULL) < bst) {
		stime(&bst);
	}
#endif
#ifdef USING_FLASH_FILESYSTEM
	return 0;
#else
	char cmd[64];
	int rc;

	snprintf(cmd, sizeof(cmd), "flatfs -r -d %s", configdir);
	rc = system(cmd);
	if (rc < 0)
		return rc;
	else if (WIFEXITED(rc))
		return WEXITSTATUS(rc);
	else
		return -1;
#endif
}

/*****************************************************************************/

static void maybewait(pid_t pid)
{
	int status;

	if (pid > 0)
		while (waitpid(pid, &status, 0) == -1 && errno == EINTR);
}

/*****************************************************************************/

/*
 * Initialise the filesystem, either from default (clobbercfg = 1)
 * or from flash.
 */

static void init_config_fs(int clobbercfg)
{
	int rc = 0;

	/* Read and validate the config */
	if (clobbercfg) {
		logd("newflatfs", "clobbered");
	} else if (read_config_from_flash() != 0) {
		/* flatfs has already logged the error */
	} else if ((rc = flat_filecount(configdir)) <= 0) {
		logd("newflatfs", "filecount=%d", rc);
	} else if (flat_needinit()) {
		logd("newflatfs", "needinit");
	} else {
		return;
	}

	/* Invalid config so reinitialise it */
#ifdef CONFIG_USER_FLATFSD_EXTERNAL_INIT
	syslog(LOG_ERR, "Nonexistent or bad flatfs (%d), requesting new one...", rc);
	flat_requestinit();
#else
	syslog(LOG_ERR, "Nonexistent or bad flatfs (%d), creating new one...", rc);
	flat_clean();
	if ((rc = flat_new(DEFAULTDIR)) < 0) {
		syslog(LOG_ERR, "Failed to create new flatfs, err=%d errno=%d",
			rc, errno);
		exit(1);
	}
	maybewait(save_config_to_flash());
#endif
}

/*****************************************************************************/

/*
 * Default the config filesystem.
 */

static pid_t reset_config_fs(void)
{
	int rc;

	printf("Resetting configuration\n");
	logd("resetconfig", NULL);

	/*
	 * Don't actually clean out the filesystem.
	 * That will be done when we reboot
	 */
	if ((rc = flat_requestinit()) < 0) {
		syslog(LOG_ERR, "Failed to prepare flatfs for reset (%d): %m", rc);
		exit(1);
	}

	return save_config_to_flash();
}

/*****************************************************************************/

static int creatpidfile(void)
{
	FILE	*f;
	pid_t	pid;
	char	*pidfile = "/var/run/flatfsd.pid";

	pid = getpid();
	if ((f = fopen(pidfile, "w")) == NULL) {
		syslog(LOG_ERR, "Failed to open %s: %m", pidfile);
		return -1;
	}
	fprintf(f, "%d\n", pid);
	fclose(f);
	return 0;
}

/*****************************************************************************/

/*
 * Lodge ourselves with the kernel LED manager. If it gets an
 * interrupt from the reset switch it will send us a SIGUSR2.
 */

static int register_resetpid(void)
{
#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
	int	fd;

	if ((fd = open("/dev/ledman", O_RDONLY)) < 0) {
		syslog(LOG_ERR, "Failed to open /dev/ledman: %m");
		return -1;
	}
	if (ioctl(fd, LEDMAN_CMD_SIGNAL, 0) < 0) {
		syslog(LOG_ERR, "Failed to register pid: %m");
		return -2;
	}
	close(fd);
#endif
	return 0;
}

/*****************************************************************************/

#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
#define CHECK_FOR_SIG(x) \
	do { usleep(x); if (recv_usr1 || recv_usr2 || recv_pwr || recv_hup) goto skip_out; } while(0)
#else
#define CHECK_FOR_SIG(x) \
	do { usleep(x); if (recv_usr1 || recv_usr2 || recv_pwr || recv_hup) return; } while(0)
#endif

static void led_pause(void)
{
	unsigned long start = time(0);

#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
	ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_ALL); /* all leds on */
	ledman_cmd(LEDMAN_CMD_ON | LEDMAN_CMD_ALTBIT, LEDMAN_ALL); /* all leds on */
	CHECK_FOR_SIG(100000);
	ledman_cmd(LEDMAN_CMD_OFF | LEDMAN_CMD_ALTBIT, LEDMAN_ALL); /* all leds off */
	CHECK_FOR_SIG(100000);
	ledman_cmd(LEDMAN_CMD_ON | LEDMAN_CMD_ALTBIT, cmd_list[current_cmd].led);
	CHECK_FOR_SIG(250000);
#endif

	while (time(0) - start < cmd_list[current_cmd].timeout) {
		CHECK_FOR_SIG(250000);
	}

#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
	ledman_cmd(LEDMAN_CMD_ON | LEDMAN_CMD_ALTBIT, LEDMAN_ALL); /* all leds on */
#endif
	action |= cmd_list[current_cmd].action;
	current_cmd = 0;

#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
skip_out:
	ledman_cmd(LEDMAN_CMD_RESET | LEDMAN_CMD_ALTBIT, LEDMAN_ALL);
	ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_ALL); /* all leds on */
#endif
}

/*****************************************************************************/

static void usage(int rc)
{
	printf("usage: flatfsd [-a|-b|-H|-P|-c|-r|-w|-i|-s|-v|-h|-?] [-n1234] "
		"[-d <dir>] [-f <file>]\n"
		"\t-a <action> send a command to the running flatfsd\n"
		"\t-b safely reboot the system\n"
		"\t-H safely halt the system\n"
		"\t-P safely power the system off\n"
		"\t-c check that the saved flatfs is valid\n"
		"\t-d <dir> with -r to read from flash to an alternate filesystem\n"
		"\t   and -s to save an alternate config to flash\n"
		"\t-f <file> file or device node for flatfs storage\n"
		"\t-r read from flash, write to config filesystem\n"
		"\t-w read from default, write to config filesystem\n"
		"\t-n with -r or -w, do not write to flash\n"
		"\t-i initialise from default, reboot\n"
		"\t-s save config filesystem to flash\n"
		"\t-S save config filesystem to flash (rate limited)\n"
		"\t-1 force use of version 1 flash layout\n"
		"\t-2 force use of version 2 flash layout\n"
		"\t-3 force use of version 3 flash layout\n"
		"\t-4 force use of version 4 flash layout (default)\n"
		"\t-v print version\n"
		"\t-h this help\n");
	exit(rc);
}

/*****************************************************************************/

static void version(void)
{
	printf("flatfsd " FLATFSD_VERSION "\n");
}

/*****************************************************************************/

static int saveconfig(void)
{
	if (writesocket("write") == 0)
		printf("Saving configuration\n");
	else {
		log_caller("flatfsd-s");
		maybewait(save_config_to_flash());
	}
	return 0;
}

static int dirtyconfig(void)
{
	if (writesocket("dirty") == 0)
		printf("Marking configuration dirty\n");
	else {
		log_caller("flatfsd-dirty");
		maybewait(save_config_to_flash());
	}
	return 0;
}

static int reboot_system(void)
{
	if (writesocket("reboot") == 0) {
		printf("Rebooting system\n");
		return 0;
	} else {
		log_caller("flatfsd-b");
		reboot_now();
		/*notreached*/
		return 1;
	}
}

static int halt_system(void)
{
	if (writesocket("halt") == 0) {
		printf("Halting system\n");
		return 0;
	} else {
		log_caller("flatfsd-h");
		halt_now();
		/*notreached*/
		return 1;
	}
}

static int poweroff_system(void)
{
	if (writesocket("poweroff") == 0) {
		printf("Powering off system\n");
		return 0;
	} else {
		log_caller("flatfsd-p");
		poweroff_now();
		/*notreached*/
		return 1;
	}
}


static int reset_config(void)
{
	if (writesocket("reset") == 0) {
		printf("Reset config\n");
		return 0;
	} else {
		log_caller("flatfsd-i");
		maybewait(reset_config_fs());
		reboot_now();
		/*notreached*/
		return 1;
	}
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	const char *actionval = NULL;
	struct sigaction act;
	struct timeval timeout;
	fd_set fds;
	time_t dirtyprev, now;
	pid_t pid;
	int fd, sockfd, dirtydelay, rc;

	openlog("flatfsd", LOG_PERROR|LOG_PID, LOG_DAEMON);

	action = 0;
	while ((rc = getopt(argc, argv, "a:vcd:f:nribwHP1234hsS?")) != EOF) {
		switch (rc) {
		case 'a':
			action = rc;
			actionval = optarg;
			break;
		case 'n':
			nowrite = 1;
			break;
		case 'd':
			configdir = optarg;
			if (access(configdir, R_OK | W_OK) < 0) {
				printf("%s: directory does not exist or "
					"is not writeable\n", configdir);
				exit(1);
			}
			break;
		case 'f':
			filefs = optarg;
			if (access(filefs, R_OK | W_OK) < 0) {
				printf("%s: storage file does not exist or "
					"is not writeable\n", filefs);
				exit(1);
			}
			break;
		case 'v':
			version();
			exit(0);
			break;
		case 'w':
		case 'r':
		case 'c':
		case 's':
		case 'S':
		case 'b':
		case 'H':
		case 'P':
		case 'i':
			action = rc;
			break;
		case '1':
			fsver = 1;
			break;
		case '2':
			fsver = 2;
			break;
		case '3':
			fsver = 3;
			break;
		case '4':
			fsver = 4;
			break;
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	switch (action) {
		case 'a':
			exit(writesocket(actionval));
			break;
		case 'w':
			init_config_fs(1);
			exit(0);
			break;
		case 'r':
			init_config_fs(0);
			exit(0);
			break;
		case 'c':
			check_config();
			break;
		case 's':
			exit(saveconfig());
			break;
		case 'S':
			exit(dirtyconfig());
			break;
		case 'b':
			exit(reboot_system());
			break;
		case 'H':
			exit(halt_system());
			break;
		case 'P':
			exit(poweroff_system());
			break;
		case 'i':
			exit(reset_config());
			break;
	}

	fd = open("/proc/self/oom_score_adj", O_WRONLY);
	if (fd >= 0) {
		write(fd, "-1000", 5);
		close(fd);
	} else {
		fd = open("/proc/self/oom_adj", O_WRONLY);
		if (fd >= 0) {
			write(fd, "-17", 3);
			close(fd);
		}
	}

	sockfd = createsocket();
	creatpidfile();

	memset(&act, 0, sizeof(act));
	act.sa_handler = sighup;
	act.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigcont;
	act.sa_flags = SA_RESTART;
	sigaction(SIGCONT, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigusr1;
	act.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigusr2;
	act.sa_flags = SA_RESTART;
	sigaction(SIGUSR2, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigpwr;
	act.sa_flags = SA_RESTART;
	sigaction(SIGPWR, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sigchld;
	act.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	sigaction(SIGCHLD, &act, NULL);

	/* Make sure we don't suddenly exit while we are writing */
	memset(&act, 0, sizeof(act));
	act.sa_handler = sigexit;
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);

	register_resetpid();

	umask(0777);

	/*
	 * Spin forever, waiting for a signal to write...
	 */
	action = 0;
	dirty = 0;
	dirtyprev = time(NULL);
	dirtydelay = 2 * 60;
	pid = 0;
	for (;;) {
		FD_ZERO(&fds);
		FD_SET(sockfd, &fds);
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		if (recv_chld) {
			int status;
			pid_t pidexit;

			recv_chld = 0;
			while ((pidexit = waitpid(-1, &status, WNOHANG)) > 0) {
				if (pidexit == pid)
					pid = 0;
			}
		}

		/* Convert signals into actions.
		 * Action modifications are not atomic, so not done in
		 * signal handlers to avoid races. */
		if (recv_usr1) {
			recv_usr1 = 0;
			if (!stopped)
				action |= ACTION_WRITE;
		}

		if (recv_hup) {
			recv_hup = 0;
			if (!stopped)
				action |= ACTION_REBOOT;
		}

		if (recv_pwr) {
			recv_pwr = 0;
			if (!stopped)
				action |= ACTION_HALT;
		}

		if (recv_usr2) {
			recv_usr2 = 0;
			if (!stopped)
				action |= ACTION_BUTTON;
		}

		if (exit_flatfsd) {
			exit_flatfsd = 0;
			action |= ACTION_EXIT;
		}

		if (action & ACTION_DIRTY) {
			action &= ~ACTION_DIRTY;
			if (!dirty) {
				now = time(NULL);
				dirty = dirtyprev + dirtydelay;
				if (dirty < now) {
					dirty = now;
					dirtydelay = dirty - dirtyprev;
				}
				dirtyprev = dirty;

				/* Takes about an hour to get to the max
				 * delay of one hour.
				 */
				dirtydelay *= 2;
				if (dirtydelay > 60 * 60)
					dirtydelay = 60 * 60;
			}
		}

		if (dirty) {
			if ((action & (ACTION_REBOOT|ACTION_HALT))
					|| dirty < time(NULL))
				action |= ACTION_WRITE;
		}

		if (stopped || pid > 0 || !action) {
			/* timeout mitigates race with signals */
			if (select(sockfd+1, &fds, NULL, NULL, &timeout) < 0) {
				if (errno != EINTR)
					syslog(LOG_ERR, "Select failed: %m");
			} else if (FD_ISSET(sockfd, &fds)) {
				readsocket(sockfd);
			}
			continue;
		}

		if (action & ACTION_REBOOT_NOW) {
			/*
			 * High priority reboot after resetting config.
			 */
			action &= ~ACTION_REBOOT_NOW;
			reboot_now();
			/*notreached*/
			exit(1);
		}

		if (action & ACTION_RESET) {
			action &= ~(ACTION_RESET|ACTION_WRITE);
			action |= ACTION_REBOOT_NOW;
			dirty = 0;
			pid = reset_config_fs();
			continue;
		}

		if (action & ACTION_WRITE) {
			action &= ~ACTION_WRITE;
			dirty = 0;
			pid = save_config_to_flash();
			continue;
		}

		if (action & ACTION_REBOOT) {
			/*
			 * Make sure we do the check above first so that we
			 * commit to flash before rebooting.
			 */
			action &= ~ACTION_REBOOT;
			reboot_now();
			/*notreached*/
			exit(1);
		}

		if (action & ACTION_HALT) {
			/*
			 * Ditto for halt
			 */
			action &= ~ACTION_HALT;
			halt_now();
			/*notreached*/
			exit(1);
		}

		if (action & ACTION_POWEROFF) {
			/*
			 * Ditto for poweroff
			 */
			action &= ~ACTION_POWEROFF;
			poweroff_now();
			/*notreached*/
			exit(1);
		}

		if (action & ACTION_BUTTON) {
			logd("button", NULL);
			action &= ~ACTION_BUTTON;
			current_cmd++;
			if (current_cmd >= cmd_num) /* wrap */
				current_cmd = 0;
		}

		if (action & ACTION_EXIT)
			break;

		if (current_cmd)
			led_pause();
	}

	return 0;
}

/*****************************************************************************/
