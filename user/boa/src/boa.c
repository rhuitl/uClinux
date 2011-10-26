/* vi:set tabstop=2 cindent shiftwidth=2: */
/*
 *  Boa, an http server
 *  Copyright (C) 1995 Paul Phillips <psp@well.com>
 *  Some changes Copyright (C) 1996 Charles F. Randall <crandall@goldsys.com>
 *  Some changes Copyright (C) 1996 Larry Doolittle <ldoolitt@jlab.org>
 *  Some changes Copyright (C) 1996,97,98 Jon Nelson <nels0988@tc.umn.edu>
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

/* boa: boa.c */

#include "boa.h"
#include <grp.h>
#include "syslog.h"
#include <sys/param.h>
#ifdef SERVER_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif /*SERVER_SSL*/

int server_s;					/* boa socket */

#ifdef SERVER_SSL
#define SSL_KEYF "/etc/config/ssl_key.pem"
#define SSL_CERTF "/etc/config/ssl_cert.pem"
	int server_ssl;				/*ssl socket */
	int do_ssl = 1;					/*We want to actually perform all of the ssl stuff.*/
	int do_sock = 1;				/*We may not want to actually connect to normal sockets*/
	SSL_CTX *ctx;				/*SSL context information*/
	SSL_METHOD *meth;			/*SSL method information*/
	int ssl_server_port = 443;		/*The port that the server should listen on*/
	/*Note that per socket ssl information is stored in */
#ifdef INET6
	struct sockaddr_in6 server_sockaddr;		/* boa ssl socket address */
#else
	struct sockaddr_in ssl_server_sockaddr;		/* boa ssl socket address */
#endif/*INET6*/
extern int InitSSLStuff(void);
extern void get_ssl_request(void);
#endif /*SERVER_SSL*/

int backlog = SO_MAXCONN;
#ifdef INET6
struct sockaddr_in6 server_sockaddr;		/* boa socket address */
#else
struct sockaddr_in server_sockaddr;		/* boa socket address */
#endif

struct timeval req_timeout;		/* timeval for select */

extern char *optarg;			/* getopt */

fd_set block_read_fdset;
fd_set block_write_fdset;

int sighup_flag = 0;			/* 1 => signal has happened, needs attention */
int sigchld_flag = 0;			/* 1 => signal has happened, needs attention */
int lame_duck_mode = 0;

time_t time_counter = 0;

int sock_opt = 1;
int do_fork = 1;

static int max_fd = 0;

#ifdef EMBED
static void log_pid()
{
	FILE *f;
	pid_t pid;
	char *pidfile = "/var/run/boa.pid";

	pid = getpid();
	if((f = fopen(pidfile, "w")) == NULL)
		return;
	fprintf(f, "%d\n", pid);
	fclose(f);
}
#endif

int main(int argc, char **argv)
{
	int c;						/* command line arg */
	int s_port = 80;

	openlog("boa", LOG_PID, 0);
#ifdef SERVER_SSL
	while ((c = getopt(argc, argv, "p:vc:dns")) != -1) {
#else
	while ((c = getopt(argc, argv, "p:vc:d")) != -1) {
#endif /*SERVER_SSL*/
		switch (c) {
		case 'c':
			server_root = strdup(optarg);
			break;
		case 'v':
			verbose_logs = 1;
			break;
		case 'd':
			do_fork = 0;
			break;
#ifdef EMBED
		case 'p':
			s_port= atoi(optarg);
			break;
#endif			
#if SERVER_SSL
		case 'n':
			do_sock = 0;		/*We don't want to do normal sockets*/
			break;
		case 's':
			do_ssl = 0;		/*We don't want to do ssl sockets*/
			break;

#endif /*SERVER_SSL*/
		default:
#if 0
			fprintf(stderr, "Usage: %s [-v] [-s] [-n] [-c serverroot] [-d]\n", argv[0]);
#endif
			exit(1);
		}
	}
#ifdef EMBED
	log_pid();
#endif
	fixup_server_root();

	read_config_files();
#ifdef EMBED
	if(s_port != 80)
		set_server_port(s_port);
#endif
#ifdef BOA_TIME_LOG
	open_logs();
#endif
	create_common_env();

#ifdef SERVER_SSL
	if (do_ssl) {
		if (InitSSLStuff() != 1) {
			/*TO DO - emit warning the SSL stuff will not work*/
			syslog(LOG_ALERT, "Failure initialising SSL support - ");
			if (do_sock == 0) {
				syslog(LOG_ALERT, "    normal sockets disabled, so exiting");fflush(NULL);
				return 0;
			} else {
				syslog(LOG_ALERT, "    supporting normal (unencrypted) sockets only");fflush(NULL);
				do_sock = 2;
			}
	  }
	} else 
		do_sock = 2;
#endif /*SERVER_SSL*/

#ifdef SERVER_SSL
	if(do_sock){
#endif /*SERVER_SSL*/
#ifdef INET6
	if ((server_s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1)
#else
	if ((server_s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
#endif
		die(NO_CREATE_SOCKET);

	/* server socket is nonblocking */
	if (fcntl(server_s, F_SETFL, NOBLOCK) == -1)
		die(NO_FCNTL);

	if ((setsockopt(server_s, SOL_SOCKET, SO_REUSEADDR, (void *) &sock_opt,
					sizeof(sock_opt))) == -1)
		die(NO_SETSOCKOPT);

	/* internet socket */
#ifdef INET6
	server_sockaddr.sin6_family = AF_INET6;
	memcpy(&server_sockaddr.sin6_addr,&in6addr_any,sizeof(in6addr_any));
	server_sockaddr.sin6_port = htons(server_port);
#else
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sockaddr.sin_port = htons(server_port);
#endif

	if (bind(server_s, (struct sockaddr *) &server_sockaddr,
			 sizeof(server_sockaddr)) == -1)
		die(NO_BIND);

	/* listen: large number just in case your kernel is nicely tweaked */
	if (max_connections != -1)
		backlog = MIN(backlog, max_connections);
	if (listen(server_s, backlog) == -1)
		die(NO_LISTEN);

	if (server_s > max_fd)
		max_fd = server_s;
#ifdef SERVER_SSL
	}
#endif /*SERVER_SSL*/

	init_signals();
	/* background ourself */	

#ifndef EMBED
	if (do_fork)
		if (fork())
			exit(0);
#endif

	/* close server socket on exec 
	 * so cgi's can't write to it */

	if (fcntl(server_s, F_SETFD, 1) == -1) {
#if 0
		perror("can't set close-on-exec on server socket!");
#endif
		exit(0);
	}

	/* close STDIN on exec so cgi's can't read from it */
	if (fcntl(STDIN_FILENO, F_SETFD, 1) == -1) {
#if 0
		perror("can't set close-on-exec on STDIN!");
#endif
		exit(0);
	}
	
	/* translate paths to server_chroot */
	chroot_aliases();
	chroot_virtual_hosts();
	
#ifdef USE_CHROOT
	if (server_chroot)
	{
		if (!strncmp(server_root,server_chroot,strlen(server_chroot)))
				strcpy(server_root,server_root + strlen(server_chroot) - 
						(server_chroot[strlen(server_chroot)-1]=='/'?1:0) );
		else
		{
#ifdef BOA_TIME_LOG
			log_error_time();
			fprintf(stderr,"Warning: server_root not accessible from %s\n",
					server_chroot);
#endif
			syslog(LOG_ERR, "server root not accessible");
		}
	}
  if (server_chroot)
  {
    if (!strncmp(dirmaker,server_chroot,strlen(server_chroot)))
        strcpy(dirmaker,dirmaker + strlen(server_chroot) -
            (server_chroot[strlen(server_chroot)-1]=='/'?1:0) );
    else
    {
#ifdef BOA_TIME_LOG
      log_error_time();
      fprintf(stderr,"Warning: directory maker not accessible from %s\n",
          server_chroot);
#endif
	  syslog(LOG_ERR, "directory maker not accessible");
    }
  }
#endif
	
	auth_check();	/* Check Auth'ed directories */

	DBG(printf("main:give out privs\n");)
	/* give away our privs if we can */
#ifdef EMBED
	server_gid = getgid();
	server_uid = getuid();
#else
	if (getuid() == 0) {
		struct passwd *passwdbuf;
		passwdbuf = getpwuid(server_uid);
		if (passwdbuf == NULL)
			die(GETPWUID);
		if (initgroups(passwdbuf->pw_name, passwdbuf->pw_gid) == -1)
			die(INITGROUPS);
                if (server_chroot)
                  if (chroot(server_chroot))
                    die(CANNOT_CHROOT);
		if (setgid(server_gid) == -1)
			die(NO_SETGID);
		if (setuid(server_uid) == -1)
			die(NO_SETUID);
	} else {
		if (server_gid || server_uid) {
#ifdef BOA_TIME_LOG 
			log_error_time();
			fprintf(stderr, "Warning: "
					"Not running as root: no attempt to change to uid %d gid %d\n",
					server_uid, server_gid);
#endif
		}
		server_gid = getgid();
		server_uid = getuid();
	}
#endif /* EMBED */

	/* main loop */

	timestamp();
	FD_ZERO(&block_read_fdset);
	FD_ZERO(&block_write_fdset);
	
	status.connections = 0;
	status.requests = 0;
	status.errors = 0;
	
	while (1) {
		if (sighup_flag)
			sighup_run();
		if (sigchld_flag)
			sigchld_run();

		switch(lame_duck_mode) {
			case 1:
				lame_duck_mode_run(server_s);
                        case 2:
				if (!request_ready && !request_block)
					die(SHUTDOWN);
				break;
			default:
				break;
		}

		/* move selected req's from request_block to request_ready */
		fdset_update();

		if (!request_ready) {
			request *current;

			max_fd = 0;
			max_fd = MAX(server_s, max_fd);
#ifdef SERVER_SSL
			if (do_sock < 2)
				max_fd = MAX(server_ssl, max_fd);
#endif
			for (current = request_block; current; current = current->next) {
				max_fd = MAX(current->fd, max_fd);
				max_fd = MAX(current->data_fd, max_fd);
				max_fd = MAX(current->post_data_fd, max_fd);
			}

			if (select(max_fd + 1, &block_read_fdset, &block_write_fdset, NULL,
					   (request_block ? &req_timeout : NULL)) == -1) {
				if (errno == EINTR || errno == EBADF)
					continue;	/* while(1) */
				else
					die(SELECT);
			}
#ifdef SERVER_SSL
			if(do_sock){
				if (FD_ISSET(server_s, &block_read_fdset))
					get_request();
			}
#else
			if (FD_ISSET(server_s, &block_read_fdset))
				get_request();
#endif /*SERVER_SSL*/

#ifdef SERVER_SSL
			if (do_sock < 2) {
				if(FD_ISSET(server_ssl, &block_read_fdset)){ /*If we have the main SSL server socket*/
/*					printf("SSL request received!!\n");*/
					get_ssl_request();
				}
			} 
#endif /*SERVER_SSL*/
		}
		process_requests();		/* any blocked req's move from request_ready to request_block */
	}
}

/*
 * Name: fdset_update
 * 
 * Description: iterate through the blocked requests, checking whether
 * that file descriptor has been set by select.  Update the fd_set to
 * reflect current status.
 */

void fdset_update(void)
{
	request *current, *next;
	time_t current_time;

	current = request_block;

	current_time = time_counter;

	while (current) {
		time_t time_since;
		next = current->next;

		time_since = current_time - current->time_last;

		/* hmm, what if we are in "the middle" of a request and not
		 * just waiting for a new one... perhaps check to see if anything
		 * has been read via header position, etc... */
		if (current->kacount && (time_since >= ka_timeout) && !current->logline) {
			SQUASH_KA(current);
			free_request(&request_block, current);
		} else if (time_since > REQUEST_TIMEOUT) {
#ifdef BOA_TIME_LOG
			log_error_doc(current);
			fputs("connection timed out\n", stderr);
#endif
			SQUASH_KA(current);
			free_request(&request_block, current);
		} else if (current->buffer_end) {
			if (FD_ISSET(current->fd, &block_write_fdset))
				ready_request(current);
		} else {			
			switch (current->status) {
			case PIPE_WRITE:
			case WRITE:
				if (FD_ISSET(current->fd, &block_write_fdset))
					ready_request(current);
				else
					FD_SET(current->fd, &block_write_fdset);
				break;
			case PIPE_READ:
				if (FD_ISSET(current->data_fd, &block_read_fdset))
					ready_request(current);
				else
					FD_SET(current->data_fd, &block_read_fdset);
				break;
			case BODY_WRITE:
				if (FD_ISSET(current->post_data_fd, &block_write_fdset))
					ready_request(current);
				else
					FD_SET(current->post_data_fd, &block_write_fdset);
				break;
			default:
				if (FD_ISSET(current->fd, &block_read_fdset))
					ready_request(current);
				else
					FD_SET(current->fd, &block_read_fdset);
				break;
			}			
		}
		current = next;
	}

	if (!lame_duck_mode &&
      (max_connections == -1 || status.connections < max_connections)) { 
#ifdef SERVER_SSL
    if (do_sock) {
			FD_SET(server_s, &block_read_fdset);	/* server always set */
		}
#else
		FD_SET(server_s, &block_read_fdset);	/* server always set */
#endif /*SERVER_SSL*/
	} else {
		if (server_s != -1
#ifdef SERVER_SSL
        && do_sock
#endif
        )
			FD_CLR(server_s, &block_read_fdset);
	}

#ifdef SERVER_SSL
	if (do_sock < 2) {
		if (max_connections == -1 || status.connections < max_connections) {
		  FD_SET(server_ssl, &block_read_fdset);
 	   /* printf("Added server_ssl to fdset\n");*/
		} else {
		  FD_CLR(server_ssl, &block_read_fdset);
		}
	}
#endif /*SERVER_SSL*/

	req_timeout.tv_sec = (ka_timeout ? ka_timeout : REQUEST_TIMEOUT);
	req_timeout.tv_usec = 0l;	/* reset timeout */
}

/*
 * Name: die
 * Description: die with fatal error
 */

void die(int exit_code)
{
#ifdef BOA_TIME_LOG
	log_error_time();
	
	switch (exit_code) {
	case SERVER_ERROR:
		fputs("fatal error: exiting\n", stdout);
		break;
	case OUT_OF_MEMORY:
		perror("malloc");
		break;
	case NO_CREATE_SOCKET:
		perror("socket create");
		break;
	case NO_FCNTL:
		perror("fcntl");
		break;
	case NO_SETSOCKOPT:
		perror("setsockopt");
		break;
	case NO_BIND:
		perror("bind");
		break;
	case NO_LISTEN:
		perror("listen");
		break;
	case NO_SETGID:
		perror("setgid/initgroups");
		break;
	case NO_SETUID:
		perror("setuid");
		break;
	case NO_OPEN_LOG:
		perror("logfile fopen");	/* ??? */
		break;
	case SELECT:
		perror("select");
		break;
	case GETPWUID:
		perror("getpwuid");
		break;
	case INITGROUPS:
		perror("initgroups");
		break;
	case CANNOT_CHROOT:
                perror("chroot");
                break;
	case SHUTDOWN:
		fputs("completing shutdown\n", stderr);
		break;
	default:
		break;
	}
#endif
	syslog(LOG_WARNING, "Shutting down - %d", exit_code);
	
	fclose(stderr);
	exit(exit_code);
}

#ifdef SERVER_SSL
int
InitSSLStuff(void)
{
	syslog(LOG_NOTICE, "Enabling SSL security system");
#ifdef INET6
	if ((server_ssl = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) == -1)
	{
		die(NO_CREATE_SOCKET);
		return 0;
	}
#else
	if ((server_ssl = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
		syslog(LOG_ALERT,"Couldn't create socket for ssl");
		die(NO_CREATE_SOCKET);
		return 0;
	}
#endif /*INET6*/

	/* server socket is nonblocking */
	if (fcntl(server_ssl, F_SETFL, NOBLOCK) == -1){
		syslog(LOG_ALERT, "%s, %i:Couldn't fcntl", __FILE__, __LINE__);
		die(NO_FCNTL);
		return 0;
	}

	if ((setsockopt(server_ssl, SOL_SOCKET, SO_REUSEADDR, (void *) &sock_opt,
		sizeof(sock_opt))) == -1){
		syslog(LOG_ALERT,"%s, %i:Couldn't sockopt", __FILE__,__LINE__);
		die(NO_SETSOCKOPT);
		return 0;
	}

	/* internet socket */
#ifdef INET6
	server_sockaddr.sin6_family = AF_INET6;
	memcpy(&server_sockaddr.sin6_addr,&in6addr_any,sizeof(in6addr_any));
	server_sockaddr.sin6_port = htons(ssl_server_port);
#else
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sockaddr.sin_port = htons(ssl_server_port);
#endif

	if (bind(server_ssl, (struct sockaddr *) &server_sockaddr,
		sizeof(server_sockaddr)) == -1){
		syslog(LOG_ALERT, "Couldn't bind ssl to port %d", ntohs(server_sockaddr.sin_port));
		die(NO_BIND);
		return 0;
	}

	/* listen: large number just in case your kernel is nicely tweaked */
	if (listen(server_ssl, backlog) == -1){
		die(NO_LISTEN);
		return 0;		
	}

	if (server_ssl > max_fd)
		max_fd = server_ssl;

	/*Init all of the ssl stuff*/
//	i don't know why this line is commented out... i found it like that - damion may-02 
/*	SSL_load_error_strings();*/
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_server_method();
	if(meth == NULL){
		ERR_print_errors_fp(stderr);
		syslog(LOG_ALERT, "Couldn't create the SSL method");
		die(NO_SSL);
		return 0;
	}
	ctx = SSL_CTX_new(meth);
	if(!ctx){
		syslog(LOG_ALERT, "Couldn't create a connection context\n");
		ERR_print_errors_fp(stderr);
		die(NO_SSL);
		return 0;
	}

	if (SSL_CTX_use_certificate_file(ctx, SSL_CERTF, SSL_FILETYPE_PEM) <= 0) {
		syslog(LOG_ALERT, "Failure reading SSL certificate file: %s",SSL_CERTF);fflush(NULL);
		close(server_ssl);
		return 0;
	}
	syslog(LOG_DEBUG, "Loaded SSL certificate file: %s",SSL_CERTF);fflush(NULL);

	if (SSL_CTX_use_PrivateKey_file(ctx, SSL_KEYF, SSL_FILETYPE_PEM) <= 0) {
		syslog(LOG_ALERT, "Failure reading private key file: %s",SSL_KEYF);fflush(NULL);
		close(server_ssl);
		return 0;
	}
	syslog(LOG_DEBUG, "Opened private key file: %s",SSL_KEYF);fflush(NULL);

	if (!SSL_CTX_check_private_key(ctx)) {
		syslog(LOG_ALERT, "Private key does not match the certificate public key");fflush(NULL);
		close(server_ssl);
		return 0;
	}

	/*load and check that the key files are appropriate.*/
	syslog(LOG_NOTICE,"SSL security system enabled");
	return 1;
}
#endif /*SERVER_SSL*/
