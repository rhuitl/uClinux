/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  main.c
  
  ***************************************/


#include <sys/wait.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <syslog.h>
#include <netdb.h>
#include <time.h>
#include <stdlib.h>

#include "vscan.h"
#include "control.h"
#include "common.h"
#include "transdata.h"
#include "cache.h"
#include "os.h"
#include "ftp-cmds.h"

void run_daemon(void);
void run_with_inetd(void);
void new_connection(int fd, struct sockaddr_in client_address);
int accept_connection(struct sockaddr_in client);

void daemonify(void);
void write_pidfile(void);
int init_log(void);

static RETSIGTYPE signal_handle(int signo);
static int listen_sockfd, noforks = 0;
static int reread_flag = FALSE;

pid_t cmgrpid = 0, tdatapid = 0;
session_info *info;

/*Limit connections from single IP stuff*/
static struct client_info {
	u_int32_t ip;
	pid_t pid;
} *clients = NULL;
void add_client(pid_t, struct sockaddr_in client);
void rm_client(pid_t pid);

#ifdef ENABLE_CHANGEPROC
int main(int argc, char *argv[], char *envp[])
#else
int main(int argc, char *argv[])
#endif
{
	struct sockaddr_in listen_address;
	struct linger linger_opt = { 1, 0 };	/*Linger active, timeout 0 */
	int i;

	sstr_setopts(sstrerr, 0);
	info = NULL;

#ifdef ENABLE_CHANGEPROC
	init_set_proc_title(argc, argv, envp);
#endif
	process_cmdline(argc, argv);

	if(read_config() != 0) {
		fprintf(stderr, "Error reading configuration file\n");
		exit(1);
	}
#ifndef HAVE_NANOSLEEP
	if(config.maxulrate || config.maxdlrate) {
		write_log(ERROR, "Unable to limit transfer rate - "
			  "nanosleep() not availiable.");
		config.maxulrate = config.maxdlrate = 0;
	}
#endif
#ifndef HAVE_SETENV
#ifdef USE_CCP
	if(config.oldccp) {
		write_log(ERROR, "Unable to use old CCP method - "
			  "setenv() not availiable.");
		config.ccpcmd = NULL;
	}
#endif
#endif

	if(config.resolvhack)
		gethostbyname(config.resolvhack);
	os_init();

	if(!config.inetd && config.maxforks != 0 && !config.nodetach)
		daemonify();

	if(config.maxforksph)
		clients =
			malloc(sizeof(struct client_info) * config.maxforks);

	init_log();
	ftpcmds_init();

	signal(SIGCHLD, signal_handle);
	signal(SIGINT, signal_handle);
	signal(SIGTERM, signal_handle);
	signal(SIGHUP, signal_handle);
	signal(SIGPIPE, SIG_IGN);

	if(config.inetd) {
		run_with_inetd();
		return (0);
	}

	/*Not running from inetd */
	write_pidfile();

	/*Fork any other processes before we open the listen_sockfd */
	transdata_setup();
	do_chroot();		/*Do this before cache init to simplify local cache code */
	cache_geninit();

	listen_address = config.listen_address;
	listen_sockfd = listen_on_socket(&listen_address, NULL);
	if(listen_sockfd == -1)
		exit(1);
	i = 1;
	setsockopt(listen_sockfd, SOL_SOCKET, SO_OOBINLINE, &i, sizeof(i));
	setsockopt(listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	setsockopt(listen_sockfd, SOL_SOCKET, SO_LINGER,
		   &linger_opt, sizeof(linger_opt));


	write_log(IMPORT, "Listening on %s:%d",
		  sstr_buf(addr2name(listen_address.sin_addr)),
		  ntohs(listen_address.sin_port));

	bindtodevice(listen_sockfd);

#ifdef ENABLE_CHANGEPROC
	set_proc_title("frox: accepting connections");
#endif

	droppriv();
	run_daemon();

	return (0);
}

void run_with_inetd(void)
{
	struct sockaddr_in client_address;
	int len = sizeof(client_address);

	transdata_setup();
	do_chroot();
	droppriv();

	cache_geninit();
	vscan_init();

	if(getpeername(0, (struct sockaddr *) &client_address, &len)) {
		debug_perr("getpeername");
		die(ERROR, "Unable to establish client address from inetd",
		    0, NULL, -1);
	}

	signal(SIGHUP, SIG_IGN);
	init_session(0, client_address);
}

void run_daemon(void)
{
	struct sockaddr_in client_address;
	int len = sizeof(client_address);
	int fd;

	do {
		fd = accept(listen_sockfd,
			    (struct sockaddr *) &client_address, &len);
		if(fd < 0) {
			if(errno == EINTR)
				continue;
			debug_perr("accept");
			continue;
		}
		if(noforks == 0)
			transdata_flush();
		if(reread_flag) {
			reread_flag = FALSE;
			reread_config();
			if(config.maxforksph)
				clients =
					realloc(clients,
						sizeof(struct client_info)
						* (config.maxforksph >
						   noforks ? config.
						   maxforksph : noforks));
		}

		if(!accept_connection(client_address))
			close(fd);
		else
			new_connection(fd, client_address);
	} while(TRUE);
}

void new_connection(int fd, struct sockaddr_in client_address)
{
	pid_t pid;

	if(config.maxforks == 0) {
		close(listen_sockfd);
		signal(SIGHUP, SIG_IGN);
		signal(SIGALRM, signal_handle);
		vscan_init();
		alarm(config.timeout);
		transdata_newsocketpair();
		init_session(fd, client_address);
		exit(0);
	}

	pid = fork();
	switch (pid) {
	case -1:
		debug_perr("fork failed");
		close(fd);
		break;
	case 0:
		srand(time(NULL) + getpid());
		signal(SIGHUP, SIG_IGN);
		signal(SIGALRM, signal_handle);
		tdatapid = cmgrpid = 0;
		vscan_init();
		alarm(config.timeout);
		transdata_newsocketpair();
		init_session(fd, client_address);
		exit(0);
	default:
		close(fd);
		if(config.maxforksph)
			add_client(pid, client_address);
		noforks++;
	}
}

int accept_connection(struct sockaddr_in client)
{

	if(noforks >= config.maxforks && config.maxforks != 0) {
		write_log(ERROR,
			  "Connect from %s refused: Too many connections",
			  inet_ntoa(client.sin_addr));
		return (FALSE);
	}

	if(config.bdefend && ntohs(client.sin_port) == 20) {
		write_log(ATTACK,
			  "Connect from %s refused: Comes from ftp-data port",
			  inet_ntoa(client.sin_addr));
		return (FALSE);
	}

	if(config.maxforksph) {
		int i, x;
		for(x = 0, i = 0; x < noforks && i < config.maxforksph; x++)
			if(clients[x].ip == client.sin_addr.s_addr)
				i++;
		if(i >= config.maxforksph) {
			write_log(ERROR, "Connect from %s refused: "
				  "too many connections from that host",
				  inet_ntoa(client.sin_addr));
			return (FALSE);
		}
	}
	return (TRUE);
}


int init_log(void)
{
	time_t t;

	if(config.logfile && strcasecmp(config.logfile, "stderr")) {
		int tmpfd;
		tmpfd = open(config.logfile, O_APPEND | O_CREAT | O_WRONLY,
			     S_IRUSR | S_IWUSR);
		if(tmpfd == -1 || dup2(tmpfd, 2) == -1) {
			fprintf(stderr, "Unable to open logfile %s\n",
				config.logfile);
			return (-1);
		}
	}
	openlog("frox", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	/* These are necessary so that syslog() and ctime() can do their
	 * initialisation (specifically timezone stuff) before we chroot()
	 * and they don't have access to /etc */
	syslog(LOG_NOTICE | LOG_DAEMON, "Frox started\n");
	t = time(NULL);
	ctime(&t);
	return (0);
}

void daemonify()
{
	switch (fork()) {
	case -1:
		write_log(ERROR, "can't fork daemon");
		exit(-1);
		break;
	case 0:
		/******** child ********/
		break;
	default:
		/******** parent ********/
		exit(0);
	}

	write_log(VERBOSE, "Forked to background");
	freopen("/dev/null", "w", stdin);
	freopen("/dev/null", "w", stdout);
}

void write_pidfile(void)
{
	FILE *fp;
	pid_t pid;

	pid = getpid();

	if(config.pidfile) {
		fp = fopen(config.pidfile, "w");
		if(fp != NULL) {
			fprintf(fp, "%d\n", pid);
			fclose(fp);
		}
	}
}

void add_client(pid_t pid, struct sockaddr_in client)
{
	clients[noforks].pid = pid;
	clients[noforks].ip = client.sin_addr.s_addr;
}

void rm_client(pid_t pid)
{
	int i;

	for(i = 0; i < noforks && pid != clients[i].pid; i++);
	if(i < noforks) {
		clients[i].pid = clients[noforks].pid;
		clients[i].ip = clients[noforks].ip;
	}
}

static RETSIGTYPE signal_handle(int signo)
{
	pid_t pid;
	switch (signo) {
	case SIGCHLD:
		if(info)
			return;	/*Children do their own waitpid() */
		while((pid = waitpid(-1, (int *) 0, WNOHANG)) > 0) {
			noforks--;
			if(config.maxforksph)
				rm_client(pid);
		}
		signal(signo, signal_handle);
		break;
	case SIGINT:
	case SIGTERM:
		close(listen_sockfd);
		kill_procs();
		exit(0);
	case SIGHUP:		/*Reread config file. Not safe from signal handler. */
		reread_flag = TRUE;
		signal(signo, signal_handle);
		break;
	case SIGALRM:
		die(ERROR, "Connection timed out.", 0, NULL, -1);
	}
}
