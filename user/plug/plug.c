/*
 * PLUGDAEMON. Copyright (c) 1997 Peter da Silva. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the program and author may not be used to endorse or
 *    promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include "config.h"
#include "plug.h"

int daemonized = 0;
char *sourceaddr = 0, *sourceport = 0;
char *proxyaddr = 0;
char *prog;
int debug = 0;
int log = 0;
int sessionmode = 0;
int keepalive=0;
long timeout = 3600; /* seconds */
char tag[64];
char *pidfile = NULL, *delete_pidfile = NULL;

dest_t *dest_list;
proc_t *proc_list;
client_t *client_list;

int nproxies = 0;
int nclients = 0;
int nprocs = 0;

char *version = "plugdaemon V2.3 Copyright (c) 2001 Peter da Silva";

int
main(int ac, char **av)
{
	int srvfd, one;
	struct sockaddr_in src_sockaddr, *prx_sockaddr;
	int pid;
	dest_t *target;
	int saved_errno;

	char fd1s[12];
	char fd2s[12];
	char kals[12], dbgs[12];
	extern char **environ;
	char *cav[10];

	if (strcmp(av[0], SPAWNNAME) == 0) {
		exit(plug(ac, av));
	}
	one = 1;
	prx_sockaddr = 0;

	parse_args(ac, av);

	if (sourceaddr)
		sprintf(tag, "(%.16s %.8s)", sourceaddr, sourceport);
	else
		sprintf(tag, "(%.8s)", sourceport);

	if(debug>1)
		fprintf(stderr, "%s: %s\n", prog, tag);

	/* arguments parsed, get sockets ready */

	if ((srvfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		bailout("server socket", S_FATAL);

	if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one,
		sizeof one) < 0) {
		bailout("set server socket options", S_FATAL);
	}

	fill_sockaddr_in(&src_sockaddr,
		sourceaddr?inet_addr(sourceaddr):htonl(INADDR_ANY),
		htons(atoi(sourceport)));

	if(proxyaddr) {
		if (!(prx_sockaddr = malloc(sizeof *prx_sockaddr))) {
			bailout("alloc memory for proxy socket", S_FATAL);
		}
		fill_sockaddr_in(prx_sockaddr, inet_addr(proxyaddr), 0);
	}

	for(target = dest_list; target; target=target->next) {
		char *destaddr, *portaddr;

		destaddr = target->destname;
		if((portaddr = strchr(destaddr, ':')))
			*portaddr++ = 0;
		else
			portaddr = sourceport;

		fill_sockaddr_in(&(target->addr),
			inet_addr(destaddr), htons(atoi(portaddr)));

		target->nclients = 0;
		target->status = S_NORMAL;
		target->last_touched = (time_t)0;
		target->destname = NULL; /* it's been trashed anyway */
	}

	daemonize();

	prog = tag; /* for logging */

	init_signals();

	/* One ring to rule them all */
	if(bind(srvfd, (struct sockaddr *)&src_sockaddr, sizeof src_sockaddr) < 0)
		bailout("server bind", S_FATAL);

	if(log)
		syslog(LOG_NOTICE, "%s: Plugdaemon started.", tag);

	listen(srvfd, 5);

	/* wait for connections and service them */
	while(1) {
		int clifd, prxfd, cli_len;
		struct sockaddr_in cli_sockaddr;

		if(debug>1)
		    fprintf(stderr, "%d listening for new connections.\n",
			(int) getpid());

		cli_len = sizeof cli_sockaddr;
		do {
			clifd = accept(srvfd, (struct sockaddr *)&cli_sockaddr, &cli_len);
			saved_errno = errno;
			/* If a child process died, we'll get an interrupted
			 * system call here, so call the undertaker every time
			 * through the loop.
			 */
			undertaker();
		} while (clifd < 0 && saved_errno == EINTR);
		if(clifd < 0)
			bailout("client accept", S_FATAL);

		if(!(target = select_target(clifd))) {
			close(clifd);
			continue;
		}

		if(debug>1)
		    fprintf(stderr, "%d client connecting to %d.\n",
			(int) getpid(), ntohs(cli_sockaddr.sin_port));

		/* Create the socket for the child */
		if ((prxfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
			bailout("proxy socket", S_NONFATAL);

		if (prx_sockaddr) {
			if(bind(prxfd, (struct sockaddr *)prx_sockaddr,
				sizeof *prx_sockaddr) < 0)
			{
				bailout("proxy bind", S_NONFATAL);
			}
		}

		if (connect(prxfd, (struct sockaddr *)&(target->addr),
			    sizeof (target->addr)) < 0)
			bailout("proxy connect", S_NONFATAL);

		if(debug>1)
		    fprintf(stderr, "%d connected proxy to %s:%d.\n",
			(int) getpid(), inet_ntoa(target->addr.sin_addr),
			ntohs(target->addr.sin_port));

		if(keepalive) {
			if(setsockopt(clifd, SOL_SOCKET, SO_KEEPALIVE,
				      (char *)&one, sizeof one) < 0) {
				bailout("set client socket options", S_NONFATAL);
			}
			if(setsockopt(prxfd, SOL_SOCKET, SO_KEEPALIVE,
				      (char *)&one, sizeof one) < 0) {
				bailout("set proxy socket options", S_NONFATAL);
			}
		}
		
		sprintf(fd1s, "%d", clifd);
		sprintf(fd2s, "%d", prxfd);
		sprintf(kals, "%d", keepalive);
		sprintf(dbgs, "%d", debug);
		cav[0] = SPAWNNAME;
		cav[1] = fd1s;
		cav[2] = fd2s;
		cav[3] = kals;
		cav[4] = dbgs;
		cav[5] = NULL;

		/* spawn a child and send the parent back to try again */
		if((pid = vfork()) == -1)
			bailout("client fork", S_FATAL);

		if(pid) {
			close(prxfd);
			close(clifd);
			remember_pid(pid, target);
			update_pidfile();
			continue;
		}

		execve(PLUGPATH, cav, environ);
		_exit(S_FATAL);
	}
}

void
bailout(char *message, int status)
{
	int save_errno;
	char msgbuf[1024];
	char *p;

	save_errno = errno;

	sprintf(msgbuf, "%.64s: %.64s", prog, message);
	p = msgbuf + strlen(msgbuf);
	if(save_errno) {
		sprintf(p, ": %.64s", strerror(save_errno));
	} else {
		sprintf(p, "\nUsage is %.64s %s", prog,
			"[-V] [-P pidfile] [-klrfd[d]...] [-p proxy-addr] [-i srcaddr] [-t seconds] port destaddr[:destport]...");
	}

	if(!daemonized)
		fprintf(stderr, "%s\n", msgbuf);
	else {
		syslog(LOG_ERR, msgbuf);
		closelog();
	}

	if (status == S_NONFATAL)
		return;

	if(delete_pidfile)
		unlink(delete_pidfile);

	exit (status);
}

void
parse_args(int ac, char **av)
{
	dest_t *new_dest;
	if((prog = strrchr(*av, '/')))
		prog++;
	else
		prog = *av;

	while (*++av) {
		if (**av=='-') {
			while(*++*av) switch(**av) {
			    case 'i':
				if(!*++*av && !*++av)
					bailout("no value for -i option", S_SYNTAX);
				sourceaddr = *av;
				goto nextarg;
			    case 'p':
				if(!*++*av && !*++av)
					bailout("no value for -p option", S_SYNTAX);
				proxyaddr = *av;
				goto nextarg;
			    case 'P':
				if(!*++*av && !*++av)
					bailout("no value for -P option", S_SYNTAX);
				pidfile = *av;
				goto nextarg;
			    case 't':
				if(!*++*av && !*++av)
					bailout("no value for -t option", S_SYNTAX);
				timeout = atol(*av);
				goto nextarg;
			    case 'k':
				keepalive++;
				continue;
			    case 'l':
				log++;
				continue;
			    case 'd':
				debug++;
				continue;
			    case 'f':
				sessionmode++;
				continue;
			    case 'V':
				printf("%s: %s\n", prog, version);
				exit(0); 
			    default:
				bailout("unknown argument", S_SYNTAX);
			}
		} else {
			if(!sourceport)
				sourceport = *av;
			else  {
				char	*ptr;
				
				for (ptr = *av; *ptr != '\0'; ptr++)
					if (strchr("0123456789:.", *ptr) == NULL)
						bailout("proxy host specification not in addr[:port] format", S_SYNTAX);
				
				if(nproxies >= MAX_PROXIES)
					bailout("too many proxies", S_SYNTAX);
				new_dest = malloc(sizeof (dest_t));
				if(!new_dest) {
					perror("malloc");
					bailout("Can't allocate dest structure", S_FATAL);
				}
				new_dest->next = dest_list;
				dest_list = new_dest;
				dest_list->destname = *av;
				nproxies++;
			}
		}
nextarg:	;
	}
	if(nproxies == 0)
		bailout("not enough arguments", S_SYNTAX);
	if(!sourceport)
		bailout("not enough arguments", S_SYNTAX);
}

#define NOSET ((fd_set *) NULL)
#define NOTIME ((struct timeval *) NULL)

int
plug(int ac, char **av)
{
	struct connx {
		int fd;			/* socket (bidirectional) */
		char buf[MAX_MTU];	/* Hold STUFF */
		int len, off;		/* tail, head pointers into buffer */
		int open;		/* socket still open for reading */
		int shutdown_wait;	/* other socket closed for reading,
					 * shut down writing when your buffer
					 * is done with
					 */
	} *s;
	
	fd_set rset, wset, except_set;
	fd_set *p_eset;
	int nfds, nwr, nrd;
	int i;
	int fd1, fd2;
	
	/* Decode our arguments */
	prog = av[0];
	daemonized = 1;
	if (av[1] == NULL || av[2] == NULL || av[3] == NULL || av[4] == NULL)
		return S_FATAL;
	fd1 = atoi(av[1]);
	fd2 = atoi(av[2]);
	keepalive = atoi(av[3]);
	debug = atoi(av[4]);
	if (debug > 1)
		fprintf(stderr, "%d: spawn %s %s %s %s\n", getpid(), av[1], av[2], av[3], av[4]);
	
	s = malloc(sizeof(struct connx) * 2);
	if (s == NULL)
		bailout("connx allocation", S_FATAL);

	if(keepalive) p_eset = &except_set;
	else p_eset = NULL;

	if(fd1>fd2)
		nfds=fd1+1;
	else
		nfds=fd2+1;

	s[0].fd = fd1;
	s[1].fd = fd2;

	s[0].len = s[1].len = s[0].off = s[1].off = 0;
	s[0].open = s[1].open = 1;
	s[0].shutdown_wait = s[1].shutdown_wait = 0;

	while(s[0].open || s[1].open) {
		FD_ZERO(&rset);
		FD_ZERO(&wset);
		if(p_eset) FD_ZERO(p_eset);

		for(i = 0; i < 2; i++) {
			if(s[i].open) {
				if(p_eset) {
					FD_SET(s[i].fd, p_eset);
				}
				if(s[i].len < MAX_MTU) {
					FD_SET(s[i].fd, &rset);
				}
				if(s[i].len > s[i].off) {
					FD_SET(s[!i].fd, &wset);
				}
			}
		}

		if(select(nfds, &rset, &wset, p_eset, NOTIME) < 0)
			bailout("proxy select", S_FATAL);

		for(i = 0; i < 2; i++) {
			if(p_eset && FD_ISSET(s[i].fd, p_eset)) {
				return S_EXCEPT; /* S_NORMAL? */
			}
			if(FD_ISSET(s[i].fd, &rset)) {
				nrd = read(s[i].fd, s[i].buf+s[i].len, MAX_MTU-s[i].len);
				if(nrd == -1) { /* Shouldn't happen */
					nrd = 0; /* fake EOF */
				}
				if(nrd == 0) {
					shutdown(s[i].fd, 0);
					if(s[i].len > s[i].off)
						s[!i].shutdown_wait = 1;
					else
						shutdown(s[!i].fd, 1);
					s[i].open = 0;
				}
				s[i].len += nrd;
			}
			if(FD_ISSET(s[!i].fd, &wset)) {
				nwr = write(s[!i].fd, s[i].buf+s[i].off, s[i].len-s[i].off);
				if(nwr == 0) {
					shutdown(s[!i].fd, 1);
					shutdown(s[i].fd, 0);
					s[i].open = 0;
				} else if (nwr < 0) {
					if(errno == EAGAIN)
						nwr = 0;
					else
						bailout("proxy write", S_EXCEPT);
				}
				s[i].off += nwr;
				if(s[i].off == s[i].len) {
					s[i].off = s[i].len = 0;
					if(s[!i].shutdown_wait) {
						shutdown(s[!i].fd, 1);
						s[!i].shutdown_wait = 0;
					}
				}
			}
		}
	}
	if(debug>1) fprintf(stderr, "%d completed.\n", (int) getpid());
	return S_NORMAL;
}

void
logclient(struct in_addr peer, char *status)
{
	char *s;

	s = inet_ntoa(peer);

	syslog(LOG_NOTICE, "%.64s: Connect from %.64s %s", tag, s, status);
}

void
fill_sockaddr_in(struct sockaddr_in *buffer, u_long addr, u_short port)
{
	memset(buffer, 0, sizeof *buffer);
	buffer->sin_family = AF_INET;
	buffer->sin_addr.s_addr = addr;
	buffer->sin_port = port;
}

void
daemonize(void)
{
	int pid;
#if 0
	if(!debug) {
		if((pid = fork()) == -1)
			bailout("daemon fork", S_FATAL);
		if(pid)
			exit(S_NORMAL);
	}
#endif
	write_pidfile();

	(void)openlog(prog, LOG_PID|LOG_CONS, LOG_DAEMON);

	if(!debug) {
		close(0);
		close(1);
		close(2);
		setsid();
		daemonized = 1;
	}
}

void
cleanup(int sig)
{
	if(delete_pidfile)
		unlink(delete_pidfile);
	exit(0);
}

/* OK, all waiter() does now is squirrel away the PIDs of the dying
 * binomes, so the undertaker can deliver them to the Principle Office
 * so their resources can be reused by later children. Doing this
 * keeps them from going viral and crashing the process table, I
 * suspect Megabyte is involved somewhere. [1]
 *
 * The undertaker runs at a strategic spot in the main loop where it's
 * most likely that this bit of code will have been recently triggered.
 *
 * There's room for 1023 PIDs, or maybe 1024. Doesn't matter, if it ever
 * gets to the point that anything like that many processes are dying
 * at once this code will already be running into problems due to the
 * undertaker itself getting interrupted. The result of that will be a
 * slow memory leak in plug. I'm not sure of a better way to deal with
 * this. The best solution I have come up with is to have two sets of
 * structures for inform_undertaker to fill, and have the undertaker
 * flip them when it's entered. I'm not sure there isn't a race condition
 * there as well, so input from the bleachers is appreciated.
 */
void
waiter(int sig, SA_HANDLER_ARG2_T code, void * scp)
{
	int status, pid;

	while (1) {
		pid = waitpid(-1, &status, WNOHANG);

		if(pid == 0 || pid == -1)
			break;

		if(debug>1)
			fprintf(stderr, "%d child %d died, status is %d.\n",
				(int) getpid(), pid, status);

		switch(status) {
			case S_CONNECT:
			case S_EXCEPT:
				tag_dest_bad(pid, status);
			case S_NORMAL:
			default:
				;
		}

		inform_undertaker(pid, status);
	}
}

void
init_signals(void)
{
	struct sigaction zombiesig, junksig;

	/* Wait for dead kids */
	zombiesig.SA_HANDLER = (void *)waiter;
	sigemptyset(&zombiesig.sa_mask);
	zombiesig.sa_flags = SA_NOCLDSTOP | SA_RESTART;

	if(sigaction(SIGCHLD, &zombiesig, &junksig) < 0)
		bailout("zombie signal", S_FATAL);

	signal(SIGTERM, cleanup);
}

void delete_client (client_t *client, client_t *back_ptr)
{
	if(client->dest)
		client->dest->nclients--;
	nclients--;

	if(back_ptr)
		back_ptr->next = client->next;
	else
		client_list = client->next;
	free(client);
}

struct dtab *select_target(int clifd)
{
	struct sockaddr_in p_addr;
	int len;
	struct ctab *client = NULL;
	struct dtab *target = NULL;
	time_t now;
	int i;

	if(sessionmode || log) {
		len = sizeof p_addr;
		if(getpeername( clifd, (struct sockaddr *)&p_addr, &len) == -1)
			bailout("getpeername", S_FATAL);
	}

	if(sessionmode) {
		client_t *client = 0;
		client_t *back_ptr = 0;

		now = time((time_t *)0);

		/* find a client and get rid of expired ones */
		client = client_list;
		while(client != NULL) {
			/* Clean up expired clients as we go */
			if(now - client->last_touched > timeout) {
				delete_client(back_ptr, client);
				client = back_ptr;
			} else if(client->addr == p_addr.sin_addr.s_addr) {
				/* check to see if the dest is in failover */
			 	if(client->dest &&
				   client->dest->status != S_NORMAL) {
					delete_client(back_ptr, client);
					client = NULL;
				}
				break;
			}
			back_ptr = client;
			if (client) 
				client = client->next;
			else
				client = client_list;
		}

		if(client) { /* Old client, destination good. */
			target = client->dest;
		} else if(nclients < MAX_CLIENTS) {
			nclients++;

			client = malloc(sizeof (client_t));

			if(!client) {
				perror("malloc");
				logclient(p_addr.sin_addr,
				    "aborted: out of memory, FATAL");
				bailout("Out of memory allocating client table", S_FATAL);
			}

			client->next = client_list;
			client_list = client;

			client->addr = p_addr.sin_addr.s_addr;
			client->status = 1;
			client->dest = (struct dtab *)0;
		}

		if(client)
			client->last_touched = now;
	}

	/* New client or we're not tracking sessions */
	if(!sessionmode || !client || !client->dest) {
		static dest_t *dest_next;
		int try;
		/* select a proxy. Dumb code to cycle them */
		for(try = 0; try < nproxies; try++) {
			if(!dest_next)
				dest_next = dest_list;
			if(dest_next->status != S_NORMAL)
				continue;
			target = dest_next;
			dest_next = dest_next->next;
		}
		if(try==nproxies) { /* disaster! They're all bad! */
			/* punt, mark them all good and pick the first.
			 * This is actually not a bad strategy if the client
			 * is a web browser, since they'll just get soft
			 * failures until one comes up.
			 */
			for(dest_next = dest_list; dest_next; dest_next = dest_next->next) {
				dest_next->status = S_NORMAL;
			}
			target = dest_next = dest_list;
			dest_next = dest_next->next;
		}
		if(sessionmode && client) {
			client->dest = target;
			target->nclients++;
		}
	}

	if(log) {
		char tmp[64]; /* big enough for IPv6, in ":" fmt */
		sprintf(tmp, "to %s", inet_ntoa(target->addr.sin_addr));
		logclient(p_addr.sin_addr, tmp);
	}

	return target;
}

struct ptab *lookup_pid(int pid)
{
	proc_t *p;

	for(p = proc_list; p; p=p->next)
		if(p->pid == pid)
			break;

	return p;
}

void
remember_pid(int pid, struct dtab * target)
{
	proc_t *p = lookup_pid(pid);

	if(!p) {
		if(nprocs>=MAX_CLIENTS*USAGE_FACTOR)
			return;
		if(!(p = malloc(sizeof (proc_t))))
			return;
		p->next = proc_list;
		proc_list = p;
		nprocs++;
	}

	p->pid = pid;
	p->dest = target;
}

struct { int pid, status; } dead_children[1024];
int next_dead_child = 0;

void inform_undertaker(int pid, int status) {
	int child;

	if(next_dead_child > 1023) {
		bailout("Too many dead_children in inform_undertaker", S_FATAL);
	}
	child = next_dead_child++;

	dead_children[child].pid = pid;
	dead_children[child].status = status;
}

void undertaker(void)
{
	int pid, status, child;

	if(next_dead_child > 0) {
		while(next_dead_child > 0) {
			child = --next_dead_child;
			pid = dead_children[child].pid;
			status = dead_children[child].status;

			switch(status) {
				case S_CONNECT:
				case S_EXCEPT:
					tag_dest_bad(pid, status);
				case S_NORMAL:
				default:
					;
			}

			forget_pid(pid);
		}
	}
	update_pidfile();
}

void
forget_pid(int pid)
{
	proc_t *back_ptr = NULL;
	proc_t *p = proc_list;

	while(p) {
		if(p->pid == pid)
			break;
		back_ptr = p;
		p = p->next;
	}

	if(!p)
		return;

	if(back_ptr)
		back_ptr->next = p->next;
	else
		proc_list=p->next;
	free(p);
}

void
tag_dest_bad(int pid, int status)
{
	proc_t *p = lookup_pid(pid);

	if(!p)
		return;

	/* OK, we know this destination has failed. Change its status */
	p->dest->status = status;
}

write_pidfile()
{
	FILE *fp;
	char *msg;

	if(!pidfile) return;

	msg = malloc(strlen(pidfile)+strlen("Can't open PID file %s."));
	if(!msg)
		bailout("Can't malloc", S_FATAL);

	sprintf(msg, "Can't open PID file %s.", pidfile);
	if (!(fp = fopen(pidfile, "w"))) {
		bailout(msg, S_FATAL);
	}
	free(msg);

	fprintf(fp, "%d\n", getpid());

	fclose(fp);

	delete_pidfile = pidfile;
}

update_pidfile()
{
	FILE *fp;
	proc_t *p;

	if(!pidfile) return;
	if(!delete_pidfile) return;

	if (!(fp = fopen(pidfile, "w")))
		return;

	fprintf(fp, "%d\n", getpid());

	for(p = proc_list; p; p=p->next)
		fprintf(fp, "%d\n", p->pid);

	fclose(fp);

	delete_pidfile = pidfile;
}

/* [1] No, I do really know why the corruption occurred. I don't really
 * believe there are little animated 1s and 0s in computers, let alone
 * blue viruses with metal teeth. That's a nice white coat but I don't
 * think I need it.
 */
