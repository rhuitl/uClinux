
/*

    File: pop3.c
  
    Copyright (C) 1999, 2004, 2005 Wolfgang Zekoll <wzk@quietsche-entchen.de>
  
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
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <signal.h>
#include <netdb.h>
#include <netinet/in.h>
#include <syslog.h>
#include <time.h>
#include <wait.h>

#if defined (__linux__)
#  include <linux/types.h>
#  include <linux/netfilter_ipv4.h>
#endif

#include "ip-lib.h"
#include "pop3.h"
#include "procinfo.h"
#include "lib.h"



int normalize(char *line)
{
	int	c, i;

	noctrl(line);
	for (i=0; (c = line[i]) != 0; i++) {
		if (c < ' '  ||  c > 127)
			line[i] = ' ';
		}

	return (0);
}


int cfputd(pop3_t *x, char *line)
{
	char	buffer[4100];

	noctrl(line);
	snprintf (buffer, sizeof(buffer) - 2, "%s\r\n", line);
	if (write(1, buffer, strlen(buffer)) != strlen(buffer)) {
		printerror(1, "-ERR", "broken connection, error= lost client while writing, client= %s, user= %s",
				x->client.name, x->client.username);
		}

	return (0);
}

char *cfgets(pop3_t *x, char *line, int size)
{
	char	*p;

	*line = 0;
	if ((p = readline_fd(x, &x->client.bio, line, size, 0)) == NULL)
		return (NULL);
	else if (debug != 0)
		fprintf (stderr, "CLI >>>: %s\n", p);

	normalize(line);
	return (line);
}

int cfputs(pop3_t *x, char *line, int log)
{
	char	buffer[4100];

	noctrl(line);
	if (debug)
		fprintf (stderr, ">>> CLI: %s\n", line);

	if (log != 0  &&  log <= extendedlog)
		printerror(0, "RESP", "%s", line);

	snprintf (buffer, sizeof(buffer) - 2, "%s\r\n", line);
	if (write(1, buffer, strlen(buffer)) != strlen(buffer)) {
		printerror(1, "-ERR", "broken connection, error= lost client while writing, client= %s, user= %s",
				x->client.name, x->client.username);
		}

	return (0);
}

char *sfgets(pop3_t *x, char *line, int size, int clienttimer)
{
	char *p;

	*line = 0;
	if ((p = readline_fd(x, &x->server.bio, line, size, clienttimer)) == NULL)
		return (NULL);
	else if (debug != 0)
		fprintf (stderr, "SVR >>>: %s\n", p);

	normalize(line);
	return (line);
}

int sfputs(pop3_t *x, char *line)
{
	char	buffer[4100];

	noctrl(line);
	if (debug)
		fprintf (stderr, ">>> SVR: %s\n", line);

	snprintf (buffer, sizeof(buffer) - 2, "%s\r\n", line);
	write(x->server.bio.fd, buffer, strlen(buffer));

	return (0);
}


int sfgetr(pop3_t *x, char *line, int size)
{
	char	*p, word[80];

	if ((p = sfgets(x, line, size, 0)) == NULL)
		printerror(1, "-ERR", "broken connection, error= lost server");

	get_word(&p, word, sizeof(word));
	if (strcasecmp(word, "-ERR") == 0)
		return (1);
	else if (strcasecmp(word, "+OK") != 0)
		printerror(1, "-ERR", "invalid response from server: %s", line);

	return (0);
}

int sfputc(pop3_t *x, char *command, char *parameter, char *line, int size, char **here)
{
	int	rc;
	char	*p, buffer[300];

	if (command != NULL  &&  *command != 0) {
		if (parameter != NULL  &&  *parameter != 0)
			snprintf (buffer, sizeof(buffer) - 2, "%s %s", command, skip_ws(parameter));
		else
			copy_string(buffer, command, sizeof(buffer));

		sfputs(x, buffer);
		}

	rc = sfgetr(x, line, size);
	if (here != NULL) {
		char	word[80];

		p = line;
		get_word(&p, word, sizeof(word));
		*here = skip_ws(p);
		}

	return (rc);
}




int log_clientsuccess(pop3_t *x)
{
	unsigned long now;
	FILE	*fp;

	if (*x->logfile == 0)
		return (0);

	if ((fp = fopen(x->logfile, "w")) == NULL) {
		printerror(0, "-INFO", "can't open file: %s, error= %s",
				x->logfile, strerror(errno));
		}
	else {
		now = time(NULL);
		fprintf (fp, "%lu %s %s %s\n", now, x->client.ipnum, x->client.username, x->server.name);
		fclose (fp);
		}

	return (0);
}

int search_allowlist(char *server, char *list)
{
	char	*p, pattern[200];

	if (list == NULL  ||  *list == 0) {
		
		/*
		 * Kann eigentlich auch nicht vorkommen, wird vorher
		 * getestet.
		 */

		return (0);
		}

	p = list;
	while ((p = skip_ws(p)), *get_quoted(&p, ',', pattern, sizeof(pattern)) != 0) {
		noctrl(pattern);
		if (strpcmp(server, pattern) == 0)
			return (1);
		}
	
	return (0);
}

void doquit(pop3_t *x)
{
	cfputs(x, "+OK closing connection", 1);
	printerror(0, "+OK", "closing connection to %s", x->client.name);

	exit (0);
}


int run_acp(pop3_t *x)
{
	int	rc, pid, pfd[2];
	char	line[300];
	
	if (*x->config->acp == 0)
		return (0);

	rc = 0;
	if (pipe(pfd) != 0)
		printerror(1, "-ERR", "can't pipe: error= %s", strerror(errno));
	else if ((pid = fork()) < 0)
		printerror(1, "-ERR", "can't fork acp: error= %s", strerror(errno));
	else if (pid == 0) {
		int	argc;
		char	*argv[32];

		close(0);		/* Das acp kann nicht vom client lesen. */
		dup2(pfd[1], 2);	/* stderr wird vom parent gelesen. */
		close(pfd[0]);

		copy_string(line, x->config->acp, sizeof(line));
		argc = split(line, argv, ' ', 30);
		argv[argc] = NULL;
		execvp(argv[0], argv);

		printerror(1, "-ERR", "can't exec acp %s: error= %s", argv[0], strerror(errno));
		exit (1);
		}
	else {
		int	len;
		char	message[300];

		close(pfd[1]);
		*message = 0;
		if ((len = read(pfd[0], message, sizeof(message) - 2)) < 0)
			len = 0;

		message[len] = 0;
		noctrl(message);
		

		if (waitpid(pid, &rc, 0) < 0) {
			printerror(1, "-ERR", "error while waiting for acp, error= %s", strerror(errno));
			exit (1);
			}

		rc = WIFEXITED(rc) != 0? WEXITSTATUS(rc): 1;
		if (*message == 0)
			copy_string(message, rc == 0? "access granted": "access denied", sizeof(message));

		if (*message != 0)
			printerror(0, "", "%s (rc= %d)", message, rc);
		}
		
	return (rc);
}


int dologin(pop3_t *x)
{
	int	k;
	char	*p, word[80], line[300];


	writestatfile(x, "LOGIN");

	/*
	 * Read username and password from client.
	 */

	k = 0;
	while (1) {
		if (k >= 6) {
			printerror(1, "-ERR", "bad login sequence: %s", x->client.name);
			exit (1);
			}

		k++;
		if ((p = cfgets(x, line, sizeof(line))) == NULL) {
			printerror(1, "-ERR", "broken connection, error= lost client, client= %s",
						x->client.name);
			}

		get_word(&p, word, sizeof(word));
		strupr(word);

		if (strcmp(word, "USER") == 0) {
			get_word(&p, x->client.username, sizeof(x->client.username));
			cfputs(x, "+OK password required", 1);
			}
		else if (strcmp(word, "PASS") == 0) {
			if (*x->client.username == 0) {
				cfputs(x, "-ERR give USER first", 1);
				continue;
				}

			/*
			 * The status reply is sent later when we know if
			 * the login is correct.
			 */

			get_word(&p, x->client.password, sizeof(x->client.password));
			break;
			}
		else if (strcmp(word, "QUIT") == 0) {
			doquit(x);
			}
		else {
			cfputs(x, "-ERR login first", 1);
			}
		}


	/*
	 * I changed the logic of server selection -- 06JAN06wzk
	 *
	 *   1. The proxy evaluates earlier if the connection is
	 * redirected or not, overwriting server selection login
	 * when the proxy has a redirected connection.  If the
	 * proxy is configured for redirection and this is a
	 * redirected connection the upstream server is simple
	 * overwritten with the original requested server.
	 *
	 *   2. Before it was significant if proxy redirection
	 * was configured or not.  Now it is if the proxy has
	 * a redirected connection and the redirection mode is
	 * not to simply accept (without doing anything).
	 * 
	 * With these changes it should be possible to run the
	 * proxy in redirection and server-selection mode,
	 * redirect when requested and select server otherwise.
	 */

	if (*x->origdst.ipnum != 0  &&  x->config->redirmode != REDIR_ACCEPT) {
		if (x->config->redirmode != REDIR_FORWARD  &&
		    x->config->redirmode != REDIR_FORWARD_ONLY) {

			/*
			 * This can not happen since origdst.ipnum is only
			 * set if some kind of FORWARD is configured,
			 * see proxy_request() below. -- 06JAN06wzk
			 */

			printerror(1, "-ERR", "internal server error, error= unallowed redirected connection");
			}


		snprintf (x->server.name, sizeof(x->server.name) - 2, "%s:%u",
			x->origdst.ipnum, x->origdst.port);
		}

	else if (x->config->selectserver != 0) {

		/*
		 * Get server name if running in `server select' mode.
		 */

		if (*x->config->serverdelim == 0)
			strcpy(x->config->serverdelim, "@");

		if ((k = strcspn(x->client.username, x->config->serverdelim)) > 0) {
			x->client.username[k++] = 0;
			copy_string(x->server.name, &x->client.username[k], sizeof(x->server.name));
			}

		if (*x->server.name == 0) {

			/*
			 * No server in user login name, let's use the default
			 * server if we have one.
			 */

			if (x->config->defaultserver == 0) {
				cfputs(x, "-ERR bad login", 1);
				printerror(1, "-ERR", "login failed, client= %s, user= %s, error= missing servername",
						x->client.name, x->client.username);
				}

			copy_string(x->server.name, x->config->server, sizeof(x->server.name));
			}


		/*
		 * Check again if we have a server or not.
		 */

		if (*x->server.name == 0  ||  strcmp(x->server.name, "-") == 0) {
			cfputs(x, "-ERR bad login", 1);
			printerror(1, "-ERR", "no server selected, client= %s, user= %s",
					x->client.name, x->client.username);
			}


		/*
		 * If we have a list of permitted servers, search the server
		 * on that list.
		 */

		if (x->config->serverlist != NULL  &&  *x->config->serverlist != 0) {
			if (search_allowlist(x->server.name, x->config->serverlist) == 0) {
				cfputs(x, "-ERR bad login", 1);
				printerror(1, "-ERR", "server not on list: %s, user= %s", x->server.name, x->client.username);
				}
			}
		}
	else {
		/*
		 * If we are neither redirected (with redirmode != REDIR_ACCEPT)
		 * nor have server selection configured we use the server from
		 * the command line.
		 */

		copy_string(x->server.name, x->config->server, sizeof(x->server.name));
		}	


	/*
	 * If present take proxy username and password.
	 */

	if ((p = strchr(x->client.username, ':')) != NULL) {
		*p++ = 0;
		copy_string(x->local.username, x->client.username, sizeof(x->local.username));
		copy_string(x->client.username, p, sizeof(x->client.username));
		}

	if ((p = strchr(x->client.password, ':')) != NULL) {
		*p++ = 0;
		copy_string(x->local.password, x->client.password, sizeof(x->local.password));
		copy_string(x->client.password, p, sizeof(x->client.password));
		}

	setvar("SERVERLOGIN", x->client.username);
	setvar("USERNAME", x->local.username);
	setvar("PASSWD", x->local.password);
	



	/*
	 * Get server name and port.
	 */

	if (*x->server.name == 0  ||  strcmp(x->server.name, "-") == 0)
		printerror(1, "-ERR", "server empty or unset, user= %s", x->client.username);

	copy_string(x->server.hostname, x->server.name, sizeof(x->server.hostname));
	x->server.port = get_port(x->server.hostname, 110);

	setvar("SERVER", x->server.hostname);
	setnumvar("SERVERPORT", x->server.port);



	/*
	 * Run acp if configured ...
	 */

	if (*x->config->acp != 0) {
		if (run_acp(x) != 0)
			exit (0);
		}


	/*
	 * ... connect to the server ...
	 */

	if ((x->server.bio.fd = openip(x->server.hostname, x->server.port, x->config->srcip, 0)) < 0) {
		cfputs(x, "-ERR bad login", 1);
		printerror(1, "-ERR", "can't connect to server, server= %s, error= %s",
				x->server.name, strerror(errno));
		}

	if (verbose != 0)
		printerror(0, "", "connected to server: %s", x->server.name);


	/*
	 * ... check on succesful server greeting ...
	 */

	if ((p = sfgets(x, line, sizeof(line), 0)) == NULL)
		printerror(1, "-ERR", "broken connection, error= lost server");

	get_word(&p, word, sizeof(word));
	strupr(word);
	if (strcmp(word, "+OK") != 0) {
		cfputs(x, "-ERR bad login", 1);
		printerror(1, "-ERR", "unexpected response from server during open: %s, user= %s", word, x->client.username);
		}


	/*
	 * ... and send the user's login.
	 */

	if (sfputc(x, "USER", x->client.username, line, sizeof(line), &p) != 0) {
		cfputs(x, "-ERR bad login", 1);
		printerror(1, "-ERR", "server error on USER: user= %s, client= %s, response= %s",
					x->client.username, x->client.name, p);
		}
	else if (sfputc(x, "PASS", x->client.password, line, sizeof(line), &p) != 0) {
		cfputs(x, "-ERR bad login", 1);
		printerror(1, "-ERR", "login failure: user= %s, client= %s, response: %s",
					x->client.name, x->client.username, p);
		}

	cfputs(x, "+OK maildrop ready", 1);
	if (verbose)
		printerror(0, "", "login accepted: user= %s, client= %s, server= %s", x->client.username, x->client.name, x->server.name);

	return (0);
}


unsigned int checknumber(char *string)
{
	char	*p;
	unsigned int num;

	num = strtoul(string, &p, 10);
	if (*p != 0)
		return (0);
	
	return (num);
}

int spoolresponse(pop3_t *x)
{
	char	line[800];

	while (readline_fd(x, &x->server.bio, line, sizeof(line), 0) != NULL) {
		cfputd(x, line);
		if (strcmp(line, ".") == 0)
			break;
		}
		
	return (0);
}

int proxy_request(config_t *config)
{
	int	errcount;
	char	*p, word[80], command[10], line[600];
	pop3_t	*x;

	x = allocate(sizeof(pop3_t));
	x->config = config;
	x->started = time(NULL);

	strcpy(x->clamav.adress, "127.0.0.1");
	x->clamav.port = 3310;
	x->config->clamav.autodirectory = 1;


	get_interface_info(0, &x->i);
	setvar("INTERFACE", x->i.ipnum);
	setnumvar("PORT", x->i.port);

	getpeerinfo(0, x->client.ipnum, sizeof(x->client.ipnum),
				x->client.name, sizeof(x->client.name), 0);
	setvar("CLIENT", x->client.ipnum);
	setvar("CLIENTNAME", x->client.name);
	printerror(0, "+INFO", "proxy connected, client= %s", x->client.name);

	if (x->config->scanmail != 0)
		getclamversion(x);

	if (*x->config->clientdir != 0) {
		struct stat sbuf;

		snprintf (x->logfile, sizeof(x->logfile) - 2, "%s/%s", x->config->clientdir, x->client.ipnum);
		if (stat(x->logfile, &sbuf) == 0) {
			if (unlink(x->logfile) != 0)
				printerror(0, "can't remove logfile: %s", x->logfile);
			}
		}



#if defined (__linux__)

	/*
	 * Get redirection data if available.
	 */

	*x->origdst.ipnum = 0;			/* Just make sure that it's `0' -- 06JAN06wzk */
	if (x->config->redirmode != 0) {
		int	rc;
		size_t	socksize;
		struct sockaddr_in sock;

		socksize = sizeof(sock);
		rc = getsockopt(0, SOL_IP, SO_ORIGINAL_DST, &sock, &socksize);
		if (rc != 0)
			;
		else if (strcmp((char *) inet_ntoa(sock.sin_addr), x->i.ipnum) != 0  ||
			 ntohs(sock.sin_port) != x->i.port) {

			/*
			 * Take the original server information if it's
			 * a redirected request.
			 */

			copy_string(x->origdst.ipnum, (char *) inet_ntoa(sock.sin_addr), sizeof(x->origdst.ipnum));
			x->origdst.port = ntohs(sock.sin_port);
			setvar("ORIGDST_SERVER", x->origdst.ipnum);
			setnumvar("ORIGDST_PORT", x->origdst.port);

			printerror(0, "+INFO", "connection redirected, origdst: %s:%u", x->origdst.ipnum, x->origdst.port);
			}

		if (x->config->redirmode == REDIR_FORWARD_ONLY  &&  *x->origdst.ipnum != 0) {
			printerror(1, "-ERR", "session error, client= %s, error= connection not redirected",
					x->client.name);
			}
		}

#endif


	/*
	 * Send the login greeting to the client, read his login information
	 * and login on the POP3 server.
	 */

	cfputs(x, "+OK server ready", 1);
	dologin(x);
	log_clientsuccess(x);

	writestatfile(x, "READY");
	errcount = 0;
	while (cfgets(x, line, sizeof(line)) != NULL) {
		if (extendedlog != 0)
			printerror(0, "", "CMD: %s", line);

		p = line;
		get_word(&p, command, sizeof(command));
		strupr(command);
		writestatfile(x, line);

		if (strcmp(command, "NOOP") == 0) {
			if (sfputc(x, "NOOP", "", line, sizeof(line), &p) != 0) {
				cfputs(x, "-ERR server error", 1);
				printerror(1, "-ERR", "server returned error response to NOOP: response= %s", line);
				}

			cfputs(x, "+OK", 1);
			}
		else if (strcmp(command, "RSET") == 0) {
			if (sfputc(x, "RSET", "", line, sizeof(line), &p) != 0) {
				cfputs(x, "-ERR server error", 1);
				printerror(1, "-ERR", "server returned error response to RSET: response= %s", line);
				}

			cfputs(x, "+OK", 1);
			}
		else if (strcmp(command, "QUIT") == 0) {
			if (sfputc(x, "QUIT", "", line, sizeof(line), &p) != 0)
				printerror(1, "-ERR", "server returned error response to QUIT: response= %s", line);

			log_clientsuccess(x);
			doquit(x);
			}
		else if (strcmp(command, "DELE") == 0) {
			get_word(&p, word, sizeof(word));
			if (*word == 0) {
				printerror(0, "-INFO", "missing DELE parameter, client= %s", x->client.name);
				cfputs(x, "-ERR missing parameter", 1);
				}
			else if (strtoul(word, &p, 10) == 0  ||  *p != 0) {
				printerror(0, "-INFO", "invalid DELE parameter: %s", word);
				cfputs(x, "-ERR bad parameter", 1);
				}
			else if (sfputc(x, "DELE", word, line, sizeof(line), &p) == 0)
				cfputs(x, "+OK message marked", 1);
			else
				cfputs(x, "-ERR", 1);
			}
		else if (strcmp(command, "LIST") == 0  ||  strcmp(command, "UIDL") == 0) {
			get_word(&p, word, sizeof(word));
			if (*word == 0) {
				if (sfputc(x, command, "", line, sizeof(line), NULL) != 0)
					cfputs(x, line, 1);
				else {
					cfputs(x, line, 1);
					spoolresponse(x);
					}
				}
			else {
				if (*(p = skip_ws(p)) != 0) {
					printerror(0, "-INFO", "too many arguments: command= %s", line);
					cfputs(x, "-ERR too many arguments", 1);
					}
				else if (checknumber(word) == 0) {
					printerror(0, "-INFO", "bad parameter: command= %s %s", command, word);
					cfputs(x, "-ERR bad argument", 1);
					}
				else {
					sfputc(x, command, word, line, sizeof(line), NULL);
					cfputs(x, line, 1);
					}
				}
			}
		else if (strcmp(command, "RETR") == 0) {
			get_word(&p, word, sizeof(word));
			if (*(p = skip_ws(p)) != 0) {
				printerror(0, "-INFO", "too many arguments: command= %s", line);
				cfputs(x, "-ERR too many parameters", 1);
				}
			else if (*word == 0) {
				printerror(0, "-INFO", "missing RETR parameter");
				cfputs(x, "-ERR missing parameter", 1);
				}
			else if (checknumber(word) == 0) {
				printerror(0, "-INFO", "invalid RETR parameter: command= %s %s", command, word);
				cfputs(x, "-ERR bad parameter", 1);
				}
			else if (sfputc(x, "RETR", word, line, sizeof(line), &p) != 0)
				cfputs(x, "-ERR no such message", 1);
			else if (x->config->scanmail != 0  ||  x->config->spamscan != 0) {
				cfputs(x, "+OK", 1);
				doscanmail(x);
				}
			else {
				cfputs(x, "+OK", 1);
				spoolresponse(x);
				}
			}
		else if (strcmp(command, "STAT") == 0) {
			if (*(p = skip_ws(p)) != 0) {
				printerror(0, "-INFO", "too many arguments to STAT: command= %s", line);
				cfputs(x, "-ERR", 1);
				}
			else if (sfputc(x, "STAT", "", line, sizeof(line), &p) != 0)
				cfputs(x, "-ERR", 1);
			else {
				unsigned long msg, bytes;
				
				msg = strtoul(p, &p, 10);
				bytes = strtoul(p, &p, 10);

				snprintf (line, sizeof(line) - 2, "+OK %lu %lu", msg, bytes);
				cfputs(x, line, 1);
				}
			}
		else if (strcmp(command, "TOP") == 0) {
			unsigned long msgno, lines;

			get_word(&p, word, sizeof(word));
			if ((msgno = checknumber(word)) == 0) {
				printerror(0, "-INFO", "bad msgno to TOP: command= %s", line);
				cfputs(x, "-ERR bad argument", 1);
				}
			else if (get_word(&p, word, sizeof(word)), *(p = skip_ws(p)) != 0) {
				printerror(0, "-INFO", "too many arguments to TOP: command= %s", line);
				cfputs(x, "-ERR too many arguments", 1);
				}
			else if (*word == 0) {
				printerror(0, "-INFO", "missing linecount to TOP: command= %s", line);
				cfputs(x, "-ERR missing argument", 1);
				}
			else if (lines = strtoul(word, &p, 10), *p != 0) {
				printerror(0, "-INFO", "bad linecount to TOP: command= %s", line);
				cfputs(x, "-ERR bad argument", 1);
				}
			else {
				char	param[80];

				snprintf (param, sizeof(param) - 2, "%lu %lu", msgno, lines);
				if (sfputc(x, "TOP", param, line, sizeof(line), NULL) != 0)
					cfputs(x, "-ERR no such message", 1);
				else {
					cfputs(x, line, 1);
					spoolresponse(x);
					}
				}
			}
		else if (strcmp(command, "LAST") == 0) {
			if (*(p = skip_ws(p)) != 0) {
				printerror(0, "-INFO", "too many arguments to LAST: command= %s", line);
				cfputs(x, "-ERR", 1);
				}
			else if (sfputc(x, "LAST", "", line, sizeof(line), &p) != 0)
				cfputs(x, "-ERR", 1);
			else {
				unsigned long msg;
				
				get_word(&p, word, sizeof(word));
				msg = strtoul(p, &p, 10);

				snprintf (line, sizeof(line) - 2, "+OK %lu", msg);
				cfputs(x, line, 1);
				}
			}
		else {
			printerror(0, "-INFO", "unknown command: %s", line);
			cfputs(x, "-ERR unkown command", 1);
			errcount++;
			if (errcount > 5) {
				printerror(0, "-INFO", "too many command errors: %s", x->client.name);
				break;
				}
			}
		}

	printerror(0, "-ERR", "closing connection, client= %s", x->client.name);
	return (0);
}

