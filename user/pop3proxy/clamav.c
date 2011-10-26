
/*

    File: clamav.c

    Copyright (C) 2004, 2005 by Wolfgang Zekoll <wzk@quietsche-entchen.de>
 
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

#include <errno.h>
#include <syslog.h>
#include <wait.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

#include "ip-lib.h"
#include "procinfo.h"
#include "pop3.h"
#include "lib.h"

#include <config/autoconf.h>

#define	IS_CLEAN		0
#define	IS_VIRUS		1
#define	IS_SPAM			2



char	tmpdir[200] =		"/tmp";

static struct _tmpfile {
    char	filename[200];
    struct _tmpfile *next;
    } *lasttmp = NULL;

static int count =		0;
static int pid =		0;

static char prefix[200] =	"";


int settmpdir(char *dir)
{
	copy_string(tmpdir, dir, sizeof(tmpdir));
	return (0);
}

static int unlink_existing(char *filename)
{
	struct stat sbuf;

	if (stat(filename, &sbuf) == 0) {
		if (unlink(filename) != 0)
			return (1);
		}
	
	return (0);
}


static void cleanup(void)
{
	struct stat sbuf;
	struct _tmpfile *tmp;

	if (pid == 0  ||  pid != getpid())
		return;

	tmp = lasttmp;
	while (tmp != NULL) {
		if (stat(tmp->filename, &sbuf) == 0) {
			unlink(tmp->filename);
			}

		/*
		 * cleanup() is called on program termination
		 * so we do not need to free the memory.
		 */

		tmp = tmp->next;
		}

	return;
}

static int init_tmplist()
{
	char	*p;
	struct _tmpfile *tmp, *next;

	if (pid == 0) {
		pid = getpid();
		atexit(cleanup);

		if ((p = getenv("TMPPREFIX")) == NULL  ||  *p == 0)
			strcpy(prefix, "pop3-");
		else
			copy_string(prefix, p, sizeof(prefix));
		}
	else if (pid != getpid()) {

		/*
		 * we are in a child process - let's erase the parent's
		 * tempfile list and create our own.
		 */

		pid     = getpid();
		count   = 0;

		tmp = lasttmp;
		while (tmp != NULL) {
			next = tmp->next;
			free(tmp);

			tmp = next;
			}
			
		lasttmp = NULL;
		if (atexit(cleanup) != 0)
			printerror(1, "-ERR", "can't register cleaup()");
		}
		
	return (0);
}

char *gettmpfile(char *filename, int size)
{
	int	fd;
	struct _tmpfile *tmp;
	static unsigned long now = 0;

	if (now == 0)
		now = time(NULL);

	init_tmplist();
	if ((tmp = malloc(sizeof(struct _tmpfile))) == NULL)
		printerror(1, "-ERR", "memory allocation error, error= %s", strerror(errno));

	snprintf (tmp->filename, sizeof(tmp->filename) - 2, "/%s/%s%ld-%05d.%03d.tmp",
			tmpdir, prefix, now, pid, ++count);
	
	tmp->next = lasttmp;
	lasttmp = tmp;

	unlink_existing(tmp->filename);
	if ((fd = open(tmp->filename, O_CREAT | O_WRONLY | O_TRUNC, 0600)) < 0) {
		printerror(1, "-ERR", "can't open tmpfile: %s, error= %s",
				tmp->filename, strerror(errno));
		}

	close (fd);
	if (filename != NULL)
		copy_string(filename, tmp->filename, size);

	return (tmp->filename);
}


int clearstring(string_t *s)
{
	s->len = 0;
	return (0);
}

char *addline(string_t *s, char *line)
{
	int	len;

	len = strlen(line);
	if (s->len + len + 20 >= s->max) {
		s->max += len + 1024;
		s->string = reallocate(s->string, s->max);
		}

	strcpy(&s->string[s->len], line);
	s->len += len;
	s->string[s->len++] = '\n';
	s->string[s->len]   = 0;

	return (s->string);
}


int getclamversion(pop3_t *x)
{
	char	*p;

	memset(&x->clamav.bio, 0, sizeof(x->clamav.bio));
	if ((x->clamav.bio.fd = openip(x->clamav.adress, x->clamav.port, NULL, 0)) < 0)
		printerror(1, "-PROXY", "can't get clamav version: error= %s", strerror(errno));

	p = "VERSION\n";
	write(x->clamav.bio.fd, p, strlen(p));
	if (readline_fd(x, &x->clamav.bio, x->clamav.version, sizeof(x->clamav.version), 0) == NULL  ||
	    *x->clamav.version == 0) {
	    	printerror(1, "-PROXY", "invalid clamav version: response= %s", x->clamav.version);
		}

	close(x->clamav.bio.fd);
	return (0);
}

int doscanmail(pop3_t *x)
{
	int	virulent, inheader;
	char	*p, status[80], virusname[200], spamlevel[80], line[4096];
	FILE	*fp;


	writestatfile(x, "RECEIVE");
	virulent = IS_CLEAN;
	*spamlevel = 0;

	x->lasttimer = time(NULL);
	if (*x->spoolfile == 0)
		gettmpfile(x->spoolfile, sizeof(x->spoolfile));


	clearstring(&x->clamav.header);
	addline(&x->clamav.header, "");
	inheader = 1;

	/*
	 * Read the e-mail from the server into a temporary spoolfile.
	 */

	if ((fp = fopen(x->spoolfile, "w")) == NULL)
		printerror(1, "-PROXY", "can't write spoolfile: filename= %s, reason= %s", x->spoolfile, strerror(errno));

	x->size = 0;
	while (readline_fd(x, &x->server.bio, line, sizeof(line), 1) != NULL) {
		x->size = x->size + strlen(line) + 1;

		if (inheader != 0) {
			addline(&x->clamav.header, line);
			if (*line == 0)
				inheader = 0;
			}


		if (*(p = line) == '.') {
			p++;
			if (*p == 0)
				break;
			}

		if (fprintf (fp, "%s\n", p) < 0) {
			fclose(fp);
			printerror(1, "-PROXY", "IO error on writing spoolfile: filename= %s, reason= %s", x->spoolfile, strerror(errno));
			/* file is removed by cleanup() which is registered with atexit() */
		}

		x->size += strlen(p) + 2;	/* e-mail line terminator is CRLF */
		}

	fclose (fp);



	/*
	 * Scan for viruses using clamav.
	 */

	if (x->config->scanmail != 0) {

		/*
		 * Connect to the local clamav server ...
		 */

		writestatfile(x, "CLAMSCAN");
		memset(&x->clamav.bio, 0, sizeof(x->clamav.bio));
		if ((x->clamav.bio.fd = openip(x->clamav.adress, x->clamav.port, NULL, 0)) < 0)
			printerror(1, "-PROXY", "can't connect to clamav daemon: error= %s", strerror(errno));


		/*
		 * ... and scan the e-mail.
		 */

		snprintf (line, sizeof(line) - 2, "CONTSCAN %s\n", x->spoolfile);
		if (debug != 0)
			fprintf (stderr, ">>> CAV: %s\n", noctrl(line));

		write(x->clamav.bio.fd, line, strlen(line));
		while (1) {
			if (readline_fd(x, &x->clamav.bio, line, sizeof(line), 1) == NULL)
				break;		/* Richtig oder falsch? */

			if (debug != 0)
				fprintf (stderr, "CAV >>>: %s\n", line);

			if ((p = strrchr(line, ' ')) == NULL)
				printerror(1, "-PROXY", "clamav protocol error: response= %s", line);

			p++;
			get_word(&p, status, sizeof(status));
			strupr(status);
#ifdef CONFIG_PROP_STATSD_STATSD
			system("statsd -a incr clamav-pop total");
#endif
			if (strcmp(status, "OK") == 0)
				break;
			else if (strcmp(status, "FOUND") == 0) {
				char	filename[200];

				p = line;
				get_quoted(&p, ':', filename, sizeof(filename));
				p = skip_ws(p);
				get_word(&p, virusname, sizeof(virusname));
				printerror(0, "-VIRUS", "found virus: virus= %s", virusname);

				snprintf (line, sizeof(line) - 2, "** virus: %s", virusname);
				addline(&x->clamav.header, line);

				virulent = IS_VIRUS;
#ifdef CONFIG_PROP_STATSD_STATSD
				system("statsd -a incr clamav-pop infected");
#endif
				}
			else
				printerror(1, "-PROXY", "clamav protocol error: response= %s", line);
			}

		close(x->clamav.bio.fd);

		/*
		 * Virulent e-mails are rewritten.
		 */

		if (virulent == IS_VIRUS) {
			char	*basename;

			basename = NULL;
			if (*x->config->clamav.quarantine != 0) {
				char	newname[200], infofile[200], *q;

				writestatfile(x, "QUARANTINE");
				if ((basename = strrchr(x->spoolfile, '/')) == NULL)
					basename = x->spoolfile;
				else
					basename++;

				q = x->config->clamav.quarantine;
				if (x->config->clamav.autodirectory != 0) {
					int	exists;
					unsigned long now;
					char	date[40];
					struct tm tm;
					struct stat sbuf;
					static char dirname[200];

					now = time(NULL);
					tm = *localtime(&now);
					strftime(date, sizeof(date) - 2, "%Y-%m-%d", &tm);
					snprintf (dirname, sizeof(dirname) - 2, "%s/%s", q, date);
					if ((exists = stat(dirname, &sbuf)) == 0  &&  S_ISDIR(sbuf.st_mode) != 0)
						q = dirname;
					else if (exists != 0  &&  mkdir(dirname, 0755) == 0)
						q = dirname;
					}

				snprintf (newname, sizeof(newname) - 6, "%s/%s", q, basename);
				if (rename(x->spoolfile, newname) != 0) {
					printerror(1, "-ERR", "can't quarantine file %s, error= %s",
							newname, strerror(errno));
					}

				copy_string(infofile, newname, sizeof(infofile));
				if ((p = strrchr(infofile, '.')) == NULL)
					printerror(0, "-ERR", "infofile filename error: %s", infofile);
				else {
					strcpy(p, ".info");
					if ((fp = fopen(infofile, "w")) == NULL) {
						printerror(1, "-ERR", "can't open infofile: %s, error= %s",
								infofile, strerror(errno));
						}
					else {
						fprintf (fp, "client: %s\n", x->client.name);
						fprintf (fp, "server: %s\n", x->server.name);
						fprintf (fp, "user: %s\n", x->client.username);
						fprintf (fp, "virus: %s\n", virusname);
						fprintf (fp, "filename: %s\n", newname);
						fprintf (fp, "size: %lu\n", x->size);
						fprintf (fp, "\n");
						fclose (fp);
						}
					}

				printerror(0, "+INFO", "quarantined e-mail: %s, virusname= %s",
						basename, virusname);
				}


			writestatfile(x, "REWRITE");
			if ((fp = fopen(x->spoolfile, "w")) == NULL)
				printerror(1, "-PROXY", "can't rewrite email: filename= %s", x->spoolfile);

			if (x->config->ident && *(x->config->ident)) {
				fprintf(fp, "From: %s\r\n", x->config->ident);
				fprintf(fp, "Subject: %s - virus found: %s\r\n", x->config->ident, virusname);
			} else {
				fprintf (fp, "From: Virus-Scanner\r\n");
				fprintf (fp, "Subject: pop3proxy - virus found: %s\r\n", virusname);
			}
			fprintf (fp, "\r\n");

			fprintf (fp, "E-Mail headers follow:\r\n");
			fprintf (fp, "\r\n");

			p = x->clamav.header.string;
			while (*p != 0) {
				get_quoted(&p, '\n', line, sizeof(line));
				fprintf (fp, ">  %s\n", line);
				}

			fprintf (fp, "\r\n");
			if (x->config->ident && *(x->config->ident)) {
				fprintf (fp, "E-Mail was blocked by %s with %s/%s using %s.\r\n",
							x->config->ident, program, VERSION, x->clamav.version);
			} else {
				fprintf (fp, "E-Mail was blocked by %s/%s using %s.\r\n",
							program, VERSION, x->clamav.version);
			}

			if (basename != NULL  &&  *basename != 0)
				fprintf (fp, "ID= %s\r\n", basename);

			fprintf (fp, "\r\n");
			fclose (fp);

			/* 
			 * Run the specified virus event program
			 * In the style of clamd's VirusEvent action
			 */

			if (*x->config->clamav.virusevent != 0) {
				pid = fork();
				if (pid == 0) {
					/* child */
					char *buffer, *pt, *cmd;

					cmd = strdup(x->config->clamav.virusevent);
					if ((pt = strstr(cmd, "%c"))) {
						buffer = (char *)allocate(strlen(cmd) + strlen(x->client.username)); 
						*pt = 0; pt += 2;
						strcpy(buffer, cmd);
						strcat(buffer, x->client.username);
						strcat(buffer, pt);
						free(cmd);
						cmd = strdup(buffer);
						free(buffer);
					}

					if ((pt = strstr(cmd, "%i"))) {
						buffer = (char *)allocate(strlen(cmd) + strlen(x->client.ipnum)); 
						*pt = 0; pt += 2;
						strcpy(buffer, cmd);
						strcat(buffer, x->client.ipnum);
						strcat(buffer, pt);
						free(cmd);
						cmd = strdup(buffer);
						free(buffer);
					}

					if ((pt = strstr(cmd, "%s"))) {
						buffer = (char *)allocate(strlen(cmd) + strlen(x->server.hostname)); 
						*pt = 0; pt += 2;
						strcpy(buffer, cmd);
						strcat(buffer, x->server.hostname);
						strcat(buffer, pt);
						free(cmd);
						cmd = strdup(buffer);
						free(buffer);
					}

					exit(system(cmd));

					/* not reached, but serves as a
					 * reminder that cmd is still
					 * allocated */
					free(cmd);
				} else if (pid < 0) {
					printerror(0, "-ERR", "can't fork virus action, error = %s", strerror(errno));
				}
			}
		}
	}


	/*
	 * Only non-virulent e-mails up to a ceratin size are scanned for spam.
	 */

	if (virulent == IS_VIRUS)
		/* do nothing with viruses */ ;
	else if (x->config->spamscan == 0)
		/* we don't have to scan for spam */ ;
	else if (x->size >= (250 * 1024)) {
		if (debug != 0)
			printerror(0, "+INFO", "e-mail to large for spam scan: size= %ld bytes", x->size);
		}
	else {
		int	rc, pid, pfd[2];

		rc = 0;
		if (pipe(pfd) != 0)
			printerror(1, "-ERR", "can't pipe: error= %s", strerror(errno));
		else if ((pid = fork()) < 0)
			printerror(1, "-ERR", "can't fork spamc: error= %s", strerror(errno));
		else if (pid == 0) {
			int	argc, fd;
			char	*argv[32], line[300];

			close(pfd[0]);
			if ((fd = open(x->spoolfile, O_RDONLY)) < 0  ||  dup2(fd, 0) != 0) {
				printerror(1, "-ERR", "can't open spoolfile: filename= %s, error= %s",
						x->spoolfile, strerror(errno));
				}

			dup2(pfd[1], 1);

			if ((fd = open("/dev/null", O_WRONLY)) < 0  ||  dup2(fd, 2) != 2) {
				printerror(0, "-INFO", "can't close stderr, error= %s",
						strerror(errno));
				close(2);	/* then simply close it */
				}


			copy_string(line, x->config->spamd.cmd, sizeof(line));
			argc = split(line, argv, ' ', 30);
			argv[argc] = NULL;
			execvp(argv[0], argv);

			printerror(1, "-ERR", "can't exec spamc %s: error= %s", argv[0], strerror(errno));
			exit (1);
			}
		else {
			char	line[300];
			bio_t	bio;

			close(pfd[1]);		/* not used */

			memset(&bio, 0, sizeof(bio_t));
			bio.fd = pfd[0];
			if (readline_fd(x, &bio, line, sizeof(line), 1) == NULL) {
				int	s;

				s = wait(&rc);
				printerror(0, "-INFO", "spamc error, pid= %d, rc= %d/%d, error= no reply from spamc",
						pid, s, rc, strerror(errno));
				}
			else {
				int	value, treshhold;

				copy_string(spamlevel, line, sizeof(spamlevel));
				if (wait(&rc) < 0) {
					printerror(0, "-INFO", "process wait error, error= %s", strerror(errno));
					rc = 0;
					}

				if (debug != 0)
					printerror(0, "+INFO", "isspam= %d, spamlevel= %s", rc, spamlevel);

				p = spamlevel;
				value = strtoul(p, &p, 10);
				if (*p != 0)
					p++;

				treshhold = strtoul(p, &p, 10);
				if (rc != 0)
					virulent = IS_SPAM;
				}

			close(pfd[0]);
			}

		}


	/*
	 * Now send the file to the client.
	 */

	x->lasttimer = 0;
	writestatfile(x, (virulent == IS_VIRUS)? "FORWARDING": "VIRULENT");

	if ((fp = fopen(x->spoolfile, "r")) == NULL)
		printerror(1, "-PROXY", "can't open spoolfile: filename= %s, reason= %s", x->spoolfile, strerror(errno));


	/*
	 * Send some additional header.
	 */

	if (x->config->scanmail != 0) {
		snprintf (line, sizeof(line) - 2, "X-Proxy-Scanned: %s/%s %s", program, VERSION, x->clamav.version);
		cfputd(x, line);
		}

	if (x->config->spamscan != 0) {
		snprintf (line, sizeof(line) - 2, "X-Spam-Score: %s, %s",
				(virulent == IS_SPAM)? "yes": "no", spamlevel);
		cfputd(x, line);
		}


	/*
	 * Now send the e-mail to the client.
	 */

	inheader = 0;
	if (virulent == IS_SPAM  &&  *x->config->spamd.spamtag != 0)
		inheader = 1;

	while (fgets(line, sizeof(line), fp) != NULL) {
		static char buffer[4100];

		if (*(p = line) == '.')
			snprintf (p = buffer, sizeof(line), ".%s", line);

		if (inheader == 1) {
			if (*line == 0)
				inheader = 0;
			else {
				if (virulent == IS_SPAM) {
					char	*r, word[80], buffer[4100];

					r = line;
					get_word(&r, word, sizeof(word));
					if (strcasecmp(word, "subject:") != 0)
						p = line;
					else {
						snprintf (p = buffer, sizeof(buffer) - 2, "%s %s %s",
								word, x->config->spamd.spamtag, skip_ws(r));
						}
					}
				}
			}

		cfputd(x, p);
		}

	fclose (fp);
	cfputd(x, ".");
	if (virulent == IS_VIRUS)
		*x->spoolfile = 0;	/* New spoolfile for next e-mail. */

	return (0);
}

