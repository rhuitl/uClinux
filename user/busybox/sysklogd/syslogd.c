/* vi: set sw=4 ts=4: */
/*
 * Mini syslogd implementation for busybox
 *
 * Copyright (C) 1999-2004 by Erik Andersen <andersen@codepoet.org>
 *
 * Copyright (C) 2000 by Karl M. Hegbloom <karlheg@debian.org>
 *
 * "circular buffer" Copyright (C) 2001 by Gennady Feldman <gfeldman@gena01.com>
 *
 * Maintainer: Gennady Feldman <gfeldman@gena01.com> as of Mar 12, 2001
 *
 * Licensed under the GPL v2 or later, see the file LICENSE in this tarball.
 */

#include "libbb.h"
#define SYSLOG_NAMES
#define SYSLOG_NAMES_CONST
#include <syslog.h>

#include <paths.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <config/autoconf.h>

#if ENABLE_FEATURE_REMOTE_LOG
#include <netinet/in.h>
#endif

#if ENABLE_FEATURE_IPC_SYSLOG
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#endif

#include "syslogd.h"

#ifdef CONFIG_USER_FLATFSD_FLATFSD
	#define DEFAULT_CONFIG_FILE "/etc/config/syslogd.conf"
#else
	#define DEFAULT_CONFIG_FILE "/etc/syslogd.conf"
#endif

/* Path to the unix socket */
static char lfile[MAXPATHLEN];

#define MAXLINE             1024	/* maximum line length */

/* Global config handle */
static syslogd_config_t *syslogd_config;

static int reload_config;

static int load_config(syslogd_config_t *config, char *argv[]);

#ifdef DEBUG_TO_FILE
void debug_printf(const char *format, ...)
{
	static FILE *fh;

	va_list args;
	va_start(args, format);

	if (!fh) {
		fh = fopen("/tmp/syslogd.out", "a");
		fprintf(fh, "--------------------------------\n");
	}
	vfprintf(fh, format, args);
	va_end(args);
	fputc('\n', fh);
	fflush(fh);
}
#endif

static void logOneMessage(int pri, const char *msg, const char *timestamp, struct timeval *tv)
{
	struct tm *tm;
	static char res[20] = "";
	char iso_time[22];
	const char *content;
	syslogd_target_t *target;
	char buf[1024];
	char prefix_name_buf[32];
	unsigned char prefix_copy_len = 0;

	memset(prefix_name_buf, '\0', 32);
	
#ifndef EMBED
	CODE *c_pri, *c_fac;

	if (pri != 0) {
		for (c_fac = facilitynames;
			 c_fac->c_name && !(c_fac->c_val == LOG_FAC(pri) << 3); c_fac++);
		for (c_pri = prioritynames;
			 c_pri->c_name && !(c_pri->c_val == LOG_PRI(pri)); c_pri++);
		if (c_fac->c_name == NULL || c_pri->c_name == NULL) {
			snprintf(res, sizeof(res), "<%d>", pri);
		} else {
			snprintf(res, sizeof(res), "%s.%s", c_fac->c_name, c_pri->c_name);
		}
	}
#else
	snprintf(res, sizeof(res), "<%d>", pri);
#endif

	if (syslogd_config->iso) {
		tm = localtime(&tv->tv_sec);
		snprintf(iso_time, 22,  "(%.4d%.2d%.2dT%.2d%.2d%.2d%.3lu) ",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
			tm->tm_min, tm->tm_sec, tv->tv_usec / 1000);
		content = strchr(msg, ' ');
		if (content && (*(content - 1) == ':')) {
			prefix_copy_len = ((unsigned char)(content - msg)<32) ?
				               (unsigned char)(content - msg) : 31;
			strncpy(prefix_name_buf, msg, prefix_copy_len);
			content++;
		} else {
			content = "";
			iso_time[0] = '\0';
		}
	} else {
		content = "";
		iso_time[0] = '\0';
	}

	debug_printf("About to send message to all targets. res=%s, iso_time=%s msg=%s", res, iso_time, msg);

	for (target = &syslogd_config->local.common; target; target = target->next) {
		if (LOG_PRI(pri) > target->level) {
			debug_printf("skipping message at pri %d when target level is %d", LOG_PRI(pri), target->level);
			continue;
		}
		debug_printf("Accepting message at pri %d when target level is %d", LOG_PRI(pri), target->level);

		{
#ifdef EMBED
			const char *r1, *r2;
			r1 = "";
			r2 = "";
			if (target->target == SYSLOG_TARGET_REMOTE) {
				syslogd_remote_config_t *remote = (syslogd_remote_config_t *)target;
				r1 = " ";
				r2 = remote->name ?: syslogd_config->local_hostname;
			}
#endif

			debug_printf("Creating message:");
			debug_printf("res=%s", res);
			debug_printf("timestamp=%s", timestamp);
			debug_printf("msg=%s", msg);
			debug_printf("iso_time=%s", iso_time);
			debug_printf("content=%s", content);

#ifdef EMBED
			snprintf(buf, sizeof(buf) - 1, "%s%s%s%s %s %s%s\n", res, timestamp, 
					r1, r2,
					(prefix_copy_len > 0) ? prefix_name_buf : msg, iso_time, content);
#else
			snprintf(buf, sizeof(buf) - 1, "%s %s %s %s\n", timestamp, syslogd_config->local_hostname, res, msg);
#endif
			debug_printf("Created message: %s", buf);
		}
		switch (target->target) {
			case SYSLOG_TARGET_LOCAL:
				debug_printf("Logging to local target");
				log_local_message((syslogd_local_config_t *)target, buf);
				break;

#ifdef CONFIG_FEATURE_REMOTE_LOG
			case SYSLOG_TARGET_REMOTE:
				debug_printf("Logging to remote target");
				log_remote_message((syslogd_remote_config_t *)target, buf);
				break;
#endif

#ifdef CONFIG_USER_SMTP_SMTPCLIENT
			case SYSLOG_TARGET_EMAIL:
				debug_printf("Logging to email target");
				log_email_message((syslogd_email_config_t *)target, buf);
				break;
#endif
			default:
				debug_printf("Skipping unknown target");
				break;
		}
	}
	debug_printf("done message");
}

int syslog_name_to_pri(const char *name)
{
	CODE *c_pri;

	for (c_pri = prioritynames; c_pri->c_name; c_pri++) {
		if (strcmp(c_pri->c_name, name) == 0) {
			return c_pri->c_val;
		}
	}

	return -1;
}

/* Format should include trailing newline */
void syslog_local_message(const char *format, ...)
{
	char buf[256];

	va_list args;
	va_start(args, format);

	debug_printf("syslog_local_message: format=%s, syslogd_config=%p, local=%p", format, syslogd_config, &syslogd_config->local);

	vsnprintf(buf, sizeof(buf) - 1, format, args);

	debug_printf("syslog_local_message: done vsnprintf()");

	log_local_message(&syslogd_config->local, buf);
	va_end(args);
}

void syslog_message(int pri, const char *msg)
{
	struct timeval tv;
	char *timestamp;

	/* Count messages repeats */
	static int repeats = 0;
	static int old_pri = 0;
	static char old_msg[MAXLINE + 1];

	gettimeofday(&tv,NULL);

	if (strlen(msg) < 16 || msg[3] != ' ' || msg[6] != ' ' ||
			msg[9] != ':' || msg[12] != ':' || msg[15] != ' ') {
		timestamp = ctime(&(tv.tv_sec)) + 4;
		timestamp[15] = '\0';
	} else {
		timestamp = (char *) msg;
		timestamp[15] = '\0';
		msg += 16;
	}

	/* Now, is this a duplicate? */
	if (!syslogd_config->repeat && pri == old_pri && strcmp(msg, old_msg) == 0) {
		/* Yes, so remember it but don't log it */
		repeats++;
		return;
	} else {
		/* No */
		if (repeats) {
			/* Not a repeat, but we previously had repeats, so output a message */
			snprintf(old_msg, sizeof(old_msg), "last message repeated %d time(s)", repeats);
			logOneMessage(old_pri, old_msg, timestamp, &tv);
			repeats = 0;
		}

		/* Remember the previous message */
		old_pri = pri;
		strncpy(old_msg, msg, sizeof(old_msg));
		old_msg[MAXLINE] = 0;
	}

	debug_printf("About to logOneMessage: pri=%d, msg=%s", pri, msg);

	/* Log this message */
	logOneMessage(pri, msg, timestamp, &tv);
}

static void quit_signal(int sig)
{
	syslog_message(LOG_SYSLOG | LOG_INFO, "syslogd: System log daemon exiting.");
	unlink(lfile);
	if (ENABLE_FEATURE_IPC_SYSLOG)
		ipcsyslog_cleanup();
	kill_myself_with_sig(sig);
}

static void reload_signal(int sig ATTRIBUTE_UNUSED)
{
	syslog_message(LOG_SYSLOG | LOG_INFO, "syslogd: Reloading configuration...");
	reload_config = 1;

	signal(SIGHUP, reload_signal);
}

/* Don't inline: prevent struct sockaddr_un to take up space on stack
 * permanently */
static NOINLINE int create_socket(void)
{
	struct sockaddr_un sunx;
	int sock_fd;
	char *dev_log_name;

	memset(&sunx, 0, sizeof(sunx));
	sunx.sun_family = AF_UNIX;

	/* Unlink old /dev/log or object it points to. */
	/* (if it exists, bind will fail) */
	strcpy(sunx.sun_path, "/dev/log");
	dev_log_name = xmalloc_follow_symlinks("/dev/log");
	if (dev_log_name) {
		safe_strncpy(sunx.sun_path, dev_log_name, sizeof(sunx.sun_path));
		free(dev_log_name);
	}
	unlink(sunx.sun_path);

	sock_fd = xsocket(AF_UNIX, SOCK_DGRAM, 0);
	debug_printf("created socket");
	xbind(sock_fd, (struct sockaddr *) &sunx, sizeof(sunx));
	debug_printf("did bind");
	chmod("/dev/log", 0666);

	return sock_fd;
}

/* This must be a #define, since when CONFIG_DEBUG and BUFFERS_GO_IN_BSS are
 * enabled, we otherwise get a "storage size isn't constant error. */
static int serveConnection (char* tmpbuf, int n_read)
{
	int    pri_set = 0;
	char  *p = tmpbuf;

	/* SOCK_DGRAM messages do not have the terminating NUL,  add it */
	if (n_read > 0)
		tmpbuf[n_read] = '\0';

	while (p < tmpbuf + n_read) {

		int           pri = (LOG_USER | LOG_NOTICE);
		char          line[ MAXLINE + 1 ];
		char         *q = line;

		while (q < &line[ sizeof (line) - 1 ]) {
			if (!pri_set && *p == '<') {
			/* Parse the magic priority number. */
				pri = 0;
				p++;
				while (isdigit(*p)) {
					pri = 10 * pri + (*p - '0');
					p++;
				}
				if (pri & ~(LOG_FACMASK | LOG_PRIMASK)){
					pri = (LOG_USER | LOG_NOTICE);
				}
				pri_set = 1;
			} else if (*p == '\0') {
				pri_set = 0;
				*q = *p++;
				break;
			} else if (*p == '\n') {
				*q++ = ' ';
			} else if (iscntrl(*p) && (*p < 0177)) {
				*q++ = '^';
				*q++ = *p ^ 0100;
			} else {
				*q++ = *p;
			}
			p++;
		}
		*q = '\0';
		p++;
		/* Now log it */
		if (q > line)
			syslog_message (pri, line);
	}
	return n_read;
}

static void do_syslogd(char *argv[]) ATTRIBUTE_NORETURN;
static void do_syslogd(char *argv[])
{
	int sock_fd;
	fd_set fds;

	/* Set up signal handlers. */
	bb_signals(0
		+ (1 << SIGINT)
		+ (1 << SIGTERM)
		+ (1 << SIGQUIT)
		, quit_signal);
	signal(SIGHUP, reload_signal);
	signal(SIGCHLD, SIG_IGN);

	debug_printf("init local");
	init_local_targets(syslogd_config);
#ifdef CONFIG_FEATURE_REMOTE_LOG
	debug_printf("init remote");
	init_remote_targets(syslogd_config);
#endif
#ifdef CONFIG_USER_SMTP_SMTPCLIENT
	debug_printf("init email");
	init_email_targets(syslogd_config);
#endif

	/* Create the syslog file so realpath() can work. */
	if (realpath(_PATH_LOG, lfile) != NULL) {
		unlink(lfile);
	}

	debug_printf("done realpath");

	sock_fd = create_socket();

#ifdef CONFIG_FEATURE_IPC_SYSLOG
	if (syslogd_config->local.circular_logging) {
		ipcsyslog_init();
		debug_printf("created circular log");
	}
#endif

	debug_printf("about to log startup message");

	syslog_message(LOG_SYSLOG | LOG_INFO, "syslogd: started, BusyBox v" BB_VER);

	for (;;) {
		debug_printf("wait for message");

		FD_ZERO(&fds);
		FD_SET(sock_fd, &fds);

		if (reload_config) {
			char *p;

			shutdown_local_targets(syslogd_config);
#ifdef CONFIG_FEATURE_REMOTE_LOG
			shutdown_remote_targets(syslogd_config);
#endif
#ifdef CONFIG_USER_SMTP_SMTPCLIENT
			shutdown_email_targets(syslogd_config);
#endif
			syslogd_discard_config(syslogd_config);
			load_config(syslogd_config, argv);
			/*
			 * Get hostname again.
			 */
			gethostname(syslogd_config->local_hostname, sizeof(syslogd_config->local_hostname));
			if ((p = strchr(syslogd_config->local_hostname, '.'))) {
				*p = '\0';
			}

			reload_config = 0;
			syslog_message(LOG_SYSLOG | LOG_INFO, "syslogd: configuration reloaded");
		}

		if (select(sock_fd + 1, &fds, NULL, NULL, 0) < 0) {
			if (errno == EINTR) {
				/* alarm may have happened. */
				continue;
			}
			bb_perror_msg_and_die("select error");
		}

		if (FD_ISSET(sock_fd, &fds)) {
			int i;

			RESERVE_CONFIG_BUFFER(tmpbuf, MAXLINE + 1);

			memset(tmpbuf, '\0', MAXLINE + 1);
			if ((i = recv(sock_fd, tmpbuf, MAXLINE, 0)) > 0) {
				serveConnection(tmpbuf, i);
			} else {
				bb_perror_msg_and_die("UNIX socket error");
			}
			RELEASE_CONFIG_BUFFER(tmpbuf);
		} /* FD_ISSET() */
	} /* for */
}

/* Options */
enum {
	OPTBIT_mark = 0, // -m
	OPTBIT_nofork, // -n
	OPTBIT_outfile, // -O
	OPTBIT_loglevel, // -l
	OPTBIT_small, // -S
	OPTBIT_configfile, // -f
	USE_FEATURE_ROTATE_LOGFILE(OPTBIT_filesize   ,)	// -s
	USE_FEATURE_ROTATE_LOGFILE(OPTBIT_rotatecnt  ,)	// -b
	USE_FEATURE_REMOTE_LOG(    OPTBIT_remote     ,)	// -R
	USE_FEATURE_REMOTE_LOG(    OPTBIT_localtoo   ,)	// -L
	USE_FEATURE_IPC_SYSLOG(    OPTBIT_circularlog,)	// -C

	OPT_mark        = 1 << OPTBIT_mark    ,
	OPT_nofork      = 1 << OPTBIT_nofork  ,
	OPT_outfile     = 1 << OPTBIT_outfile ,
	OPT_loglevel    = 1 << OPTBIT_loglevel,
	OPT_small       = 1 << OPTBIT_small   ,
	OPT_configfile	= 1 << OPTBIT_configfile,
	OPT_filesize    = USE_FEATURE_ROTATE_LOGFILE((1 << OPTBIT_filesize   )) + 0,
	OPT_rotatecnt   = USE_FEATURE_ROTATE_LOGFILE((1 << OPTBIT_rotatecnt  )) + 0,
	OPT_remotelog   = USE_FEATURE_REMOTE_LOG(    (1 << OPTBIT_remote     )) + 0,
	OPT_locallog    = USE_FEATURE_REMOTE_LOG(    (1 << OPTBIT_localtoo   )) + 0,
	OPT_circularlog = USE_FEATURE_IPC_SYSLOG(    (1 << OPTBIT_circularlog)) + 0,
};
#define OPTION_STR "m:nO:l:Sf:" \
	USE_FEATURE_ROTATE_LOGFILE("s:" ) \
	USE_FEATURE_ROTATE_LOGFILE("b:" ) \
	USE_FEATURE_REMOTE_LOG(    "R:" ) \
	USE_FEATURE_REMOTE_LOG(    "L"  ) \
	USE_FEATURE_IPC_SYSLOG(    "C::")
#define OPTION_DECL *opt_m, *opt_O, *opt_l, *opt_f \
	USE_FEATURE_ROTATE_LOGFILE(,*opt_s) \
	USE_FEATURE_ROTATE_LOGFILE(,*opt_b) \
	USE_FEATURE_REMOTE_LOG(    ,*opt_R) \
	USE_FEATURE_IPC_SYSLOG(    ,*opt_C = NULL)
#define OPTION_PARAM &opt_m, &opt_O, &opt_l, &opt_f \
	USE_FEATURE_ROTATE_LOGFILE(,&opt_s) \
	USE_FEATURE_ROTATE_LOGFILE(,&opt_b) \
	USE_FEATURE_REMOTE_LOG(    ,&opt_R) \
	USE_FEATURE_IPC_SYSLOG(    ,&opt_C)


static int load_config(syslogd_config_t *config, char *argv[])
{
	char OPTION_DECL;

	debug_printf("Loading config from %s to initialise", DEFAULT_CONFIG_FILE);

	/* Load the default config file */
	syslogd_load_config(DEFAULT_CONFIG_FILE, config);

	debug_printf("Loaded from default config file, parsing args");

	/* do normal option parsing */
	opt_complementary = "=0"; /* no non-option params */
	getopt32(argv, OPTION_STR, OPTION_PARAM);
#ifdef SYSLOGD_MARK
	if (option_mask32 & OPT_mark) // -m
		config->local.markinterval = xatou_range(opt_m, 0, INT_MAX/60) * 60;
#endif
	if (option_mask32 & OPT_configfile) { // -f
			/* Note: All previous command line settings will be lost */
			debug_printf("loading config from %s", optarg);
			syslogd_discard_config(config);
			syslogd_load_config(opt_f, config);
	}
	if (option_mask32 & OPT_outfile) // -O
		config->local.logfile = opt_O;
#ifdef CONFIG_FEATURE_ROTATE_LOGFILE
	if (option_mask32 & OPT_filesize) // -s
		config->local.maxsize = xatou_range(opt_s, 0, INT_MAX/1024) * 1024;
	if (option_mask32 & OPT_rotatecnt) // -b
		config->local.numfiles = xatou_range(opt_b, 0, 99);
#endif
#ifdef CONFIG_FEATURE_REMOTE_LOG
	if (option_mask32 & OPT_remotelog) { // -R
		char *p;

		syslogd_remote_config_t *remote = malloc(sizeof(*remote));
		memset(remote, 0, sizeof(*remote));
		remote->common.target = SYSLOG_TARGET_REMOTE;
		remote->common.level = LOG_DEBUG;
		remote->port = 514;
		remote->common.next = config->local.common.next;
		config->local.common.next = &remote->common;

		remote->host = opt_R;
		if ((p = strchr(remote->host, ':'))) {
			remote->port = atoi(p + 1);
			*p = '\0';
		}
	}
#endif
#ifdef CONFIG_FEATURE_IPC_SYSLOG
	if (option_mask32 & OPT_circularlog) { // -C
		if (opt_C) { // -Cn
			int shm_size;
			shm_size = xatoul_range(opt_C, 4, INT_MAX/1024) * 1024;
		}
		syslogd_config->local.circular_logging = TRUE;
	}
#endif

	return 0;
}

int syslogd_main(int argc, char **argv) MAIN_EXTERNALLY_VISIBLE;
int syslogd_main(int argc ATTRIBUTE_UNUSED, char **argv)
{
	syslogd_config_t config;
	char *p;

	load_config(&config, argv);

	/* And create a global to reference it */
	syslogd_config = &config;

	/* Store away localhost's name before the fork */
	gethostname(syslogd_config->local_hostname, sizeof(syslogd_config->local_hostname));
	p = strchr(syslogd_config->local_hostname, '.');
	if (p) {
		*p = '\0';
	}

	if ((option_mask32 & OPT_nofork) == 0) {
		bb_daemonize_or_rexec(DAEMON_CHDIR_ROOT, argv);
	}
	umask(0);
	write_pidfile("/var/run/syslogd.pid");
	do_syslogd(argv);

	return EXIT_SUCCESS;
}
