
/*

    File: main.c
  
    Copyright (C) 1999, 2004, 2005 by Wolfgang Zekoll <wzk@quietsche-entchen.de>
  
    This software is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
  
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
  
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

 */
 

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <stdarg.h>
#include <errno.h>
#include <pwd.h>

#include <syslog.h>
#include <signal.h>
#include <time.h>

#include "ip-lib.h"
#include "procinfo.h"
#include "pop3.h"
#include "lib.h"


char	*program =		"";
char	progname[80] =		"";

int	debug =			0;
int	verbose =		1;
int	extendedlog =		0;

int	daemonmode =		0;
char	bindarg[200] =		"";


	/*
	 * Error printing.
	 */

int printerror(int rc, char *type, char *format, ...)
{
	char	tag[30], error[400];
	va_list	ap;

	va_start(ap, format);
	vsnprintf (error, sizeof(error) - 2, format, ap);
	va_end(ap);

	*tag = 0;
	if (*type != 0)
		snprintf (tag, sizeof(tag) - 2, "%s: ", type);

	if (debug != 0)
		fprintf (stderr, "%s: %s%s\n", program, tag, error);
	else
		syslog(LOG_NOTICE, "%s%s", tag, error);

	if (rc != 0)
		exit (rc);

	return (0);
}



int writestatfile(pop3_t *x, char *status)
{
	char	*username;

	if (getstatfp() == NULL)
		return (0);

	username = (*x->client.username == 0)? "-": x->client.username;
	if (pi.statfp != NULL) {
		rewind(pi.statfp);
		fprintf (pi.statfp, "%s %s %u %lu %s:%u %s %s %s:%u %s:%u %s %s\n",
				PROXYNAME, program, getpid(),
				x->started,
				x->i.ipnum, x->i.port,
				x->client.ipnum, x->client.name,
				x->server.name, x->server.port,
				x->origdst.ipnum, x->origdst.port,
				username, status);
		fflush(pi.statfp);
		}

	return (0);
}


void signalhandler(int sig)
{
	printerror(0, "+INFO", "caught signal #%d", sig);
	exit(0);
}


int setuserid(config_t *config)
{
	char	*p;
	struct passwd *pw;

	if (*config->user.name == 0)
		strcpy(config->user.name, "nobody");

	if (*(p = config->user.name) >= '0'  &&  *p <= '9') {
		config->user.uid = strtoul(config->user.name, &p, 10);
		config->user.gid = 65534;
		if (*p == '.') {
			p++;
			config->user.gid = strtoul(p, &p, 10);
			}

		if (*p != 0)
			printerror(1, "-PROXY", "invalid username: username= %s", config->user.name);
		}
	else if ((pw = getpwnam(config->user.name)) != NULL) {
		config->user.uid = pw->pw_uid;
		config->user.gid = pw->pw_gid;
		}
	else
		printerror(1, "-PROXY", "no such user: username= %s", config->user.name);

	if (setregid(config->user.gid, config->user.gid) != 0)
		printerror(1, "-PROXY", "can't set gid: username= %s", config->user.name);
	else if (setreuid(config->user.uid, config->user.uid) != 0)
		printerror(1, "-PROXY", "can't set uid: username= %s", config->user.name);

	return (0);
}


	/*
	 * Some basic I/O functions.
	 */

int getc_fd(pop3_t *x, bio_t *bio, int clienttimer)
{
	int	c;
	unsigned long timeoutreached;

	if (bio->here >= bio->len) {
		int	rc, max, bytes;
		struct timeval tov;
		fd_set	available, fdset;

		bio->len = bio->here = 0;

		FD_ZERO(&fdset);
		FD_SET(bio->fd, &fdset);
		max = bio->fd;

		bytes = 0;
		timeoutreached = time(NULL) + x->config->timeout;
		while (1) {
			available = fdset;
			tov.tv_usec = 0;

			if (x->lasttimer == 0)
				tov.tv_sec = x->config->timeout;
			else {
				unsigned long t1, t2, tt;

				/*
				 * We have to watch two timeouts: the regular
				 * connection timeout (to the server) and a
				 * timeout when we send the client another
				 * header to make him happy while he's waiting
				 * that the mail transfer starts.
				 */

				t1 = timeoutreached - time(NULL);
				if (t1 < 0) {
					printerror(1, "-ERR", "connection timed out");
					}

				tt = time(NULL) - x->lasttimer;
				if (tt < 0  ||  tt > POP3_CLIENTTIMER)
					tt = 0;

				t2 = POP3_CLIENTTIMER - tt;
				if (t2 < 0) {

					/*
					 * This should not happen.
					 */

					printerror(1, "-WARNING", "negative clienttimer: t2= %lu", t2);
/*					x->lastrun = time(NULL);
 *					t2 = POP3_CLIENTTIMER - time(NULL) - x->lastrun;
 */
					}

				/*
				 * Choose the lower timeout.
				 */

				tov.tv_sec = t1 < t2? t1: t2;
				if (0  &&  extendedlog >= 2) {
					printerror(0, "*DEBUG", "timeout= %lu, t1= %lu, t2= %lu",
							tov.tv_sec, t1, t2);
					}
				}


			if (0  &&  debug != 0)
				fprintf (stderr, "select max= %d\n", max);

			rc = select(max + 1, &available, (fd_set *) NULL, (fd_set *) NULL, &tov);
			if (rc < 0) {
				printerror(0, "-PROXY", "select() error: %s", strerror(errno));
				break;
				}
			else if (rc == 0) {

				/*
				 * Some timeout happened here, let's check
				 * the header timeout?
				 */

				if (x->lasttimer > 0) {
					if (time(NULL) - x->lasttimer + 2 >= POP3_CLIENTTIMER) {
						char	header[200];

						snprintf (header, sizeof(header) - 2, "X-Timeout-Header: %lu", time(NULL));
						cfputs(x, header, 1);
						x->lasttimer = time(NULL);
						continue;
						}
					}

				printerror(0, "-ERR", "connection timed out: client= %s, server= %s",
					x->client, x->config->server);
				return (-1);
				}

			if (FD_ISSET(bio->fd, &available)) {
				if ((bytes = read(bio->fd, bio->buffer, sizeof(bio->buffer) - 2)) <= 0) {
					if (debug != 0) {
						if (bytes == 0)
							fprintf (stderr, "received zero bytes on fd %d\n", bio->fd);
						else
							fprintf (stderr, "received %d bytes on fd %d, errno= %d, error= %s\n", bytes, bio->fd, errno, strerror(errno));
						}

					return (-1);
					}

				break;
				}
			}

		bio->len  = bytes;
		bio->here = 0;
		}

	if (bio->here >= bio->len)
		return (-1);

	c = (unsigned char) bio->buffer[bio->here++];
	return (c);
}

char *readline_fd(pop3_t *x, bio_t *bio, char *line, int size, int clienttimer)
{
	int	c, k;

	*line = 0;
	size = size - 2;

	c = getc_fd(x, bio, clienttimer);
	if (c < 0)
		return (NULL);

	k = 0;
	while (c > 0  &&  c != '\n'  &&  c != 0) {
		if (k < size)
			line[k++] = c;

		c = getc_fd(x, bio, clienttimer);
		}

	line[k] = 0;
	noctrl(line);

	return (line);
}




void missing_arg(int c, char *string)
{
	if (isatty(2))
		fprintf (stderr, "%s: missing arg: -%c, %s\n", program, c, string);

	exit (-1);
}

int main(int argc, char *argv[])
{
	int	c, i, k;
	char	*p, option[80];
	config_t config;
	

	if ((p = strrchr(argv[0], '/')) == NULL)
		program = argv[0];
	else {
		copy_string(progname, &p[1], sizeof(progname));
		program = progname;
		}

	memset(&config, 0, sizeof(config_t));
	config.timeout = POP3_TIMEOUT;
	strcpy(config.serverdelim, "@");
	config.redirmode = REDIR_NONE;
	openlog(program, LOG_PID, LOG_MAIL);

	copy_string(config.spamd.cmd, SPAMC, sizeof(config.spamd.cmd));
	copy_string(config.spamd.spamtag, "[SPAM]", sizeof(config.spamd.spamtag));

	k = 1;
	while (k < argc  &&  argv[k][0] == '-'  &&  argv[k][1] != 0) {
		copy_string(option, argv[k++], sizeof(option));
		for (i=1; (c = option[i]) != 0; i++) {
			if (c == 'd')
				debug = 1;
			else if (c == 'a') {
				if (k >= argc)
					missing_arg(c, "access control program");

				copy_string(config.acp, argv[k++], sizeof(config.acp));
				}
			else if (c == 'c') {
				if (k >= argc)
					missing_arg(c, "server delimeter");

				copy_string(config.serverdelim, argv[k++], sizeof(config.serverdelim));
				}
			else if (c == 'e') {
				if (config.selectserver == 1) {
					if (k >= argc)
						missing_arg(c, "default server");

					copy_string(config.server, argv[k++], sizeof(config.server));
					config.defaultserver = 1;
					}

				config.selectserver = 1;
				}
			else if (c == 'l') {
				if (k >= argc)
					missing_arg(c, "client log directory");

				copy_string(config.clientdir, argv[k++], sizeof(config.clientdir));
				}
			else if (c == 'm')
				verbose = 0;
			else if (c == 'o') {
				if (k >= argc)
					missing_arg(c, "statdir");

				copy_string(statdir, argv[k++], sizeof(statdir));
				}
			else if (c == 'p') {
				if (*pi.pidfile == 0)
					setpidfile(PIDFILE);
				else {
					if (k >= argc)
						missing_arg(c, "pidfile");

					setpidfile(argv[k++]);
					}
				}
			else if (c == 'q') {
				if (k >= argc)
					missing_arg(c, "source ip");

				copy_string(config.srcip, argv[k++], sizeof(config.srcip));
				}
			else if (c == 'r') {
#if defined (__linux__)
				char	word[80];

				if (k >= argc)
					missing_arg(c, "redirect mode");

				copy_string(word, argv[k++], sizeof(word));
				if (strcmp(word, "none") == 0  ||  strcmp(word, "off") == 0  ||
						strcmp(word, "no") == 0) {
					config.redirmode = REDIR_NONE;
					}
				else if (strcmp(word, "accept") == 0  ||  strcmp(word, "redirect") == 0)
					config.redirmode = REDIR_ACCEPT;
				else if (strcmp(word, "forward") == 0)
					config.redirmode = REDIR_FORWARD;
				else if (strcmp(word, "forward-only") == 0)
					config.redirmode = REDIR_FORWARD_ONLY;
				else
					printerror(1, "-ERR", "bad redirect mode: %s", word);
#else
				printerror(1, "-ERR", "connection redirection not supported on this platform");
#endif
				}
			else if (c == 's') {
				if (k >= argc)
					missing_arg(c, "server list");

				config.serverlist = allocate(strlen(argv[k]) + 1);
				strcpy(config.serverlist, argv[k++]);
				}
			else if (c == 't') {
				if (k >= argc)
					missing_arg(c, "timeout");

				config.timeout = atoi(argv[k++]);
				if (config.timeout < 1)
					config.timeout = 60;
				}
			else if (c == 'u') {
				if (k >= argc)
					missing_arg(c, "username");

				copy_string(config.user.name, argv[k++], sizeof(config.user.name));
				}
			else if (c == 'v') {
				if (k >= argc)
					missing_arg(c, "varname prefix");

				copy_string(varprefix, argv[k++], sizeof(varprefix));
				}
			else if (c == 'x') {
				if (k >= argc)
					missing_arg(c, "log level");

				extendedlog = atoi(argv[k++]);
				}
			else if (c == 'X') {
				if (k >= argc)
					missing_arg(c, "virus event");

				copy_string(config.clamav.virusevent, argv[k++], sizeof(config.clamav.virusevent));
				}
			else if (c == 'y') {
				if (config.spamscan == 0)
					config.spamscan = 1;
				else {
					if (k >= argc)
						missing_arg(c, "spamc command");

					copy_string(config.spamd.cmd, argv[k++], sizeof(config.spamd.cmd));
					}
				}
			else if (c == 'z') {
				if (config.scanmail != 0) {
					if (k >= argc)
						missing_arg(c, "quarantine folder");

					copy_string(config.clamav.quarantine, argv[k++], sizeof(config.clamav.quarantine));
					}

				config.scanmail = 1;
				}
			else if (c == 'D') {
				if (daemonmode == 0)
					daemonmode = 1;
				else {
					if (k >= argc)
						missing_arg(c, "port");

					copy_string(bindarg, argv[k++], sizeof(bindarg));
					}
				}
			else if (c == 'I') {
				if (k >= argc)
					missing_arg(c, "anti-virus identification string");

				copy_string(config.ident, argv[k++], sizeof(config.ident));
			}
			else if (c == 'T') {
				if (k >= argc)
					missing_arg(c, "temporary directory");

				settmpdir(argv[k++]);
				}
			else if (c == 'V') {
				printf ("%s %s\n", program, VERSION);
				exit (0);
				}
			else {
				if (isatty(2))
					fprintf (stderr, "%s: unknown option: -%c\n", program, c);

				exit (-1);
				}
			}
		}


	if (config.selectserver != 0) {
		if (k < argc) {
			if (isatty(2))
				fprintf (stderr, "%s: unexpected arguments for select server mode\n", program);

			exit (1);
			}
		}
	else {
		if (k < argc)
			copy_string(config.server, argv[k++], sizeof(config.server));
		else {
			printerror(1, "-ERR", "missing server");
			}

		if (k < argc)
			printerror(1, "-ERR", "unexpected arguments: %s", argv[k]);
		}


	atexit(exithandler);
	signal(SIGHUP, signalhandler);
	signal(SIGINT, signalhandler);
	signal(SIGQUIT, signalhandler);
	signal(SIGUSR1, signalhandler);
	signal(SIGUSR2, signalhandler);
	signal(SIGTERM, signalhandler);
	signal(SIGPIPE, signalhandler);


	/*
	 * Write the pidfile if we are in standalone mode.
	 */

	if (daemonmode != 0  &&  *pi.pidfile != 0) {
		FILE	*fp;

		if ((fp = fopen(pi.pidfile, "w")) == NULL)
			printerror(1, "-ERR", "can't write pidfile: %s, error= %s", pi.pidfile, strerror(errno));

		fprintf (fp, "%d\n", getpid());
		pi.mainpid = getpid();

		fclose (fp);
		}


	if (daemonmode != 0) {
		unsigned int port;
		int	sock;
		char	interface[80];

		*interface = 0;
		p = bindarg;
		if (strchr(p, ':') != NULL)
			get_quoted(&p, ':', interface, sizeof(interface));

		port = strtoul(p, NULL, 10);
		if (port == 0)
			port = 110;

		signal(SIGCHLD, SIG_IGN);
		sock = bind_to_port(interface, port);

/*		if (getuid() == 0)
 *			setuserid(&config);
 */
		acceptloop(sock);
		signal(SIGCHLD, SIG_DFL);
		}


	if (getuid() == 0)
		setuserid(&config);

	proxy_request(&config);

	exit (0);
}


