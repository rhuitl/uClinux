/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1996,97 Jon Nelson <nels0988@tc.umn.edu>
 *  Some changes Copyright (C) 1997 Alain Magloire <alain.magloire@rcsm.ee.mcgill.ca>
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

/* boa: signals.c */

#include "boa.h"
#include <sys/wait.h>			/* wait */
#include <signal.h>				/* signal */
 
extern time_t time_counter;

void sigsegv(int);
void sigbus(int);
void sigterm(int);
void sighup(int);
void sigint(int);
void sigchld(int);
void sigusr1(int);
void sigalrm(int);

/*
 * Name: init_signals
 * Description: Sets up signal handlers for all our friends.
 */

void init_signals(void)
{
	struct sigaction sa;

	sa.sa_flags = 0;

	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGSEGV);
	sigaddset(&sa.sa_mask, SIGBUS);
	sigaddset(&sa.sa_mask, SIGTERM);
	sigaddset(&sa.sa_mask, SIGHUP);
	sigaddset(&sa.sa_mask, SIGINT);
	sigaddset(&sa.sa_mask, SIGPIPE);
	sigaddset(&sa.sa_mask, SIGCHLD);
	sigaddset(&sa.sa_mask, SIGUSR1);
	sigaddset(&sa.sa_mask, SIGALRM);

	sa.sa_handler = sigsegv;
	sigaction(SIGSEGV, &sa, NULL);

	sa.sa_handler = sigbus;
	sigaction(SIGBUS, &sa, NULL);

	sa.sa_handler = sigterm;
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = sighup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = sigint;
	sigaction(SIGINT, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = sigchld;
	sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = sigusr1;
	sigaction(SIGUSR1, &sa, NULL);

	sa.sa_handler = sigalrm;
	sigaction(SIGALRM, &sa, NULL);
	alarm(1);
}

void sigsegv(int dummy)
{
#ifdef BOA_TIME_LOG
	log_error_time();
	fputs("caught SIGSEGV, dumping core\n", stderr);
#endif
	syslog(LOG_INFO, "caught SIGSEGV, dumping core\n");
#ifdef CRASHDEBUG
#ifdef BOA_TIME_LOG
	log_error_time();
	fputs("CRASHDEBUG enabled, dumping current request\n\n",stderr);
#endif
	syslog(LOG_INFO, "CRASHDEBUG enabled, dumping current request\n\n");
	dump_request(crashdebug_current);
#endif
	fclose(stderr);
	abort();
}

void sigbus(int dummy)
{
#ifdef BOA_TIME_LOG
	log_error_time();
	fputs("caught SIGBUS, dumping core\n", stderr);
#endif
	syslog(LOG_INFO, "caught SIGBUS, dumping core\n");
	fclose(stderr);
	abort();
}

void sigterm(int dummy)
{
	lame_duck_mode = 1;
}

void lame_duck_mode_run(int server_s)
{
    close(server_s);
#ifdef BOA_TIME_LOG
	log_error_time();
    fputs("caught SIGTERM, starting shutdown\n", stderr);
#endif
    syslog(LOG_INFO, "caught SIGTERM, starting shutdown\n");
    FD_CLR(server_s, &block_read_fdset);
    close(server_s);
    lame_duck_mode = 2;
 }



void sighup(int dummy)
{
	sighup_flag = 1;
}

void sighup_run(void)
{
	sighup_flag = 0;
#ifdef BOA_TIME_LOG
	log_error_time();
	fputs("caught SIGHUP, restarting\n", stderr);
#endif

	/* Philosophy change for 0.92: don't close and attempt reopen of logfiles,
	 * since usual permission structure prevents such reopening.
	 */

	dump_mime();
	dump_passwd();
	dump_alias();
#ifdef USE_AUTH
	dump_auth();
#endif
	free_requests();
#ifdef BOA_TIME_LOG
	log_error_time();
	fputs("re-reading configuration files\n", stderr);
#endif
	syslog(LOG_INFO, "re-reading configuration files\n");
	read_config_files();
#ifdef BOA_TIME_LOG
	log_error_time();
	fputs("successful restart\n", stderr);
#endif
	syslog(LOG_INFO, "successful restart\n");
}

void sigint(int dummy)
{
#ifdef BOA_TIME_LOG
	log_error_time();
	fputs("caught SIGINT: shutting down\n", stderr);
#endif
	syslog(LOG_INFO, "caught SIGINT: shutting down\n");
	fclose(stderr);
	exit(1);
}

void sigchld(int dummy)
{
	sigchld_flag = 1;
}

void sigchld_run(void)
{
	int status;
	pid_t pid;

	sigchld_flag = 0;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		if (verbose_cgi_logs) {
#ifdef BOA_TIME_LOG
			log_error_time();
			fprintf(stderr, "reaping child %d: status %d\n", pid, status);
#endif
			syslog(LOG_INFO, "reaping child %d: status %d\n", pid, status);
		}
	return;
}

void sigusr1(int dummy)
		
{
#ifdef BOA_TIME_LOG
	log_error_time();
	fprintf(stderr, "%ld requests, %ld errors\n", 
			status.requests, status.errors);
#endif
	syslog(LOG_INFO, "%ld requests, %ld errors, %ld connections\n", 
			status.requests, status.errors, status.connections);
}

void sigalrm(int dummy)
{
	time_counter++;
	alarm(1);
}
