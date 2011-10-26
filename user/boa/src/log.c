/* vi: set tabstop=2 cindent shiftwidth=2: */
/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1998 Martin Hinner <martin@tdp.cz>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 1, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/* boa: log.c */

#include "boa.h"

#ifdef BOA_TIME_LOG
FILE *access_log;
FILE *referer_log;
FILE *agent_log;

char *error_log_name;
char *access_log_name;
char *cgi_log_name;
char *referer_log_name;
char *agent_log_name;
#endif
int cgi_log_fd;

/*
 * Name: open_logs
 * 
 * Description: Opens up the error log, ties it to stderr, and line 
 * buffers it.
 */

void open_logs(void)
{
#ifdef BOA_TIME_LOG
	FILE *error_log;

	if (verbose_logs && access_log_name) {
		if (!(access_log = fopen(access_log_name, "a"))) {
			int errno_save = errno;
			fprintf(stderr, "Cannot open %s for logging: ", access_log_name);
			errno = errno_save;
			perror("logfile open");
			exit(1);
		}
		/* line buffer the access log */
		setvbuf(access_log, (char *) NULL, _IOLBF, 0); 
	} else
		access_log = NULL;
#ifndef NO_REFERER_LOG
	if (referer_log_name) {
		if (!(referer_log = fopen(referer_log_name, "a"))) {
			int errno_save = errno;
			fprintf(stderr, "Cannot open %s for logging: ", referer_log_name);
			errno = errno_save;
			perror("referer log open");
			exit(1);
		}
		setvbuf(referer_log,(char *)NULL,_IOLBF,0);
	} else
		referer_log = NULL;
#endif

#ifndef NO_AGENT_LOG
        if (agent_log_name) {
                if (!(agent_log = fopen(agent_log_name, "a"))) {
                        int errno_save = errno;
                        fprintf(stderr, "Cannot open %s for logging: ", agent_log_name);
                        errno = errno_save;
                        perror("agent log open");
                        exit(1);
                }
                setvbuf(agent_log,(char *)NULL,_IOLBF,0);
        } else
                agent_log = NULL;
#endif

	if (!cgi_log_name) 
		cgi_log_name = strdup("/dev/null");

	{
		cgi_log_fd = open(cgi_log_name, 
				O_WRONLY | O_CREAT | O_APPEND,
				S_IRUSR | S_IWUSR | S_IROTH | S_IRGRP);
		if (cgi_log_fd == -1) {
			log_error_time();
			perror("open cgi_log");
			free(cgi_log_name);
			cgi_log_name = NULL;
			cgi_log_fd = 0;
		} else {
			if (fcntl(cgi_log_fd, F_SETFD, 1) == -1) {
				perror("unable to set close-on-exec flag for cgi_log!");
				close(cgi_log_fd);
				cgi_log_fd = 0;
				free(cgi_log_name);
				cgi_log_name = NULL;
			}
		}
	}
	
	if (!error_log_name) {
		fputs("No ErrorLog directive specified in boa.conf.\n", stderr);
		exit(1);
	}
	if (!(error_log = freopen(error_log_name, "a", stderr)))
		die(NO_OPEN_LOG);
#endif
}

/*
 * Name: close_access_log
 * 
 * Description: closes access_log and referer_log files
 */
void close_access_log(void)
{
#ifdef BOA_TIME_LOG
	if (access_log)
		fclose(access_log);

#ifndef NO_REFERER_LOG
	if (referer_log)
		fclose(referer_log);
#endif

#ifndef NO_AGENT_LOG
        if (agent_log)
                fclose(agent_log);
#endif
#endif
}

/*
 * Name: log_access
 * 
 * Description: Writes log data to access_log.
 */

void log_access(request * req)
{
#ifdef BOA_TIME_LOG
	if (access_log) {
		if (req->host)
 			fprintf(access_log, "%s - - %s\"%s\" %d %ld \"http://%s%s\" -\n",
 				req->remote_ip_addr,
 				get_commonlog_time(),
 				req->logline,
 				req->response_status,
 				req->filepos,
 				req->host,
        req->request_uri);
		else
			fprintf(access_log, "%s - - %s\"%s\" %d %ld\n",
				req->remote_ip_addr,
				get_commonlog_time(),
				req->logline,
				req->response_status,
				req->filepos);
	}
#endif
}


/*
 * name: log_referer()
 *
 * Description: logs 'Referer:' HTTP Header line
 *   (if referer log opened).
 */

void log_referer(request *req)
{
#ifdef BOA_TIME_LOG
#ifndef NO_REFERER_LOG
        if (referer_log)
		fprintf(referer_log,"%s\n",req->referer);
#endif
#endif
}

/*
 * name: log_user_agent()
 *
 * Description: logs 'User-Agent:' HTTP Header line
 *   (if referer log opened).
 */

void log_user_agent(request *req)
{
#ifdef BOA_TIME_LOG
#ifndef NO_AGENT_LOG
        if (agent_log)
                fprintf(agent_log,"%s\n",req->user_agent);
#endif
#endif
}


/*
 * Name: log_error_time
 *
 * Description: Logs the current time to the stderr (the error log): 
 * should always be followed by an fprintf to stderr
 */

void log_error_time()
{
#ifdef BOA_TIME_LOG
	int errno_save = errno;
	fputs(get_commonlog_time(), stderr);
	errno = errno_save;
#endif
}

/*
 * Name: log_error_doc
 *
 * Description: Logs the current time and transaction identification
 * to the stderr (the error log): 
 * should always be followed by an fprintf to stderr
 *
 * This function used to be implemented with a big fprintf, but not
 * all fprintf's are reliable in the face of null string pointers
 * (SunOS, in particular).  As long as I had to add the checks for
 * null pointers, I changed from fprintf to fputs.
 *
 * Example output:
[08/Nov/1997:01:05:03] request from 192.228.331.232 "GET /~joeblow/dir/ HTTP/1.0" ("/usr/user1/joeblow/public_html/dir/"): write: Broken pipe
 */

void log_error_doc(request * req)
{
#ifdef BOA_TIME_LOG
	int errno_save = errno;
	
	fprintf(stderr, "%srequest from %s \"%s\" (\"%s%s\"): ",
			get_commonlog_time(), 
			(req->remote_ip_addr != NULL ? 
				req->remote_ip_addr : "(unknown)"),
			(req->logline != NULL ?
				req->logline : "(null)"),
			(server_chroot != NULL ?
				server_chroot : "" ),
			(req->pathname != NULL ?
				req->pathname : "(null)"));
	
	errno = errno_save;
#endif
}

/*
 * Name: boa_perror
 *
 * Description: logs an error to user and error file both
 *
 */
void boa_perror(request * req, char *message)
{
#ifdef BOA_TIME_LOG
	log_error_doc(req);
	perror(message);			/* don't need to save errno because log_error_doc does */
	send_r_error(req);
#endif
}
