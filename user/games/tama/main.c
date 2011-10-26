/*
**  Net Tamagotchi v1.1 by Milos Glisic, mglisic@lagged.net
**
**  Usage: tamad [port]
**
**  Greets go to: fredsan, m3lt, printf1, snowman
**  Xtra special thanx to Gopher for finding 78923734 bugs and making
**  it possible for Net Tamagotchi to be at least semi-stable.  
**
*/

/* includes */
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>

#ifdef _AIX
#include <strings.h>
#endif /* _AIX */

#include "tama.h"

int s;

/* Return ASCII string of current time */
char *logtime()
{
	struct tm *thetime;
	time_t utime;
	char *string;

	utime = time(NULL);
	thetime = localtime(&utime);
	string = asctime(thetime);

	string[strlen(string)-1]=0;
	return string;
}

/* SIGINT handler */
void term(int sig)
{
	/* On ^C, flush all streams and exit. */

	printf("%s Received INT signal. Exiting.\n", logtime());
	fflush(NULL);
	sleep(1);
	exit(0);
}

/* SIGALRM handler */
void timeout(int sig)
{
	/* On timeout, display error, flush all streams and exit. */

	put("\nConnection timed out. Disconnecting.\n");
	printf("%s Connection timed out. Disconnecting.\n", logtime());
	fflush(NULL);
	exit(0);
}

/* SIGSEGV handler */
void segv(int sig)
{
	put("An error has occured in the Net Tamagotchi server.\n");
	put("Please report the circumstances which caused this to algernon@debian.org\n");
	put("Thank you.\n");
	printf("%s Segmentation violation. Client handler exiting.\n", logtime());
	fflush(NULL);	
	exit(0);
}

/* SIGCHLD handler */
void chld(int sig)
{
 /* Do nothing.  Catch signal so that the select() call gets interrupted. */
}

/* read a string from the client - added compatibility */
/* for clients that use \r\n for newline, like win95 telnet */
void get(char *buf)
{
	int ctr;

	for(ctr=0; ctr<BUFLEN; ctr++) {
		if(recv(s, buf+ctr, 1, 0)<0) {
			close(s);
			exit(0);
		}
		if(buf[ctr]=='\r') ctr--;
		else if(buf[ctr]=='\n') break;
	}

	buf[ctr]='\0';
}

/* sends output to client - extended client support */
void put(char *buf)
{
	int ctr;

	for(ctr=0; ctr<strlen(buf); ctr++) {
		send(s, buf+ctr, 1, 0);
		if(buf[ctr]=='\n')
			send(s, "\r", 1, 0);
	}
}

int main(int argc, char **argv)
{
	fd_set input;
	pid_t pid;
	socklen_t fromlen;
	int rs, ns, port, fd, opt = 1, flags, clients = 0;
	struct timeval to;
	struct sockaddr_in sin, fsin;
	struct hostent *hp;
	char buf[BUFLEN], name[MAXNAME+1], *host, arg[BUFLEN], *ptr; 

	if(argc>1) {
		if(argc>2 || atoi(argv[1])==0) {
			fprintf(stderr, COMMANDLINE);
			return 1;
		} else port = atoi(argv[1]);
	} else port = PORT;

	/* Hook signals */
	(void) signal(SIGINT, term);
	(void) signal(SIGALRM, timeout);
	(void) signal(SIGSEGV, segv);
	(void) signal(SIGCHLD, chld);

	printf("%s [%d] Starting %s", logtime(), getpid(), VER);
	if((ns = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) < 0) {
		perror("socket()");
		return 1;
	}
	printf("%s Created socket: s=%d\n", logtime(), ns);

	setsockopt(ns, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));

	memset(&sin, 0, sizeof(struct sockaddr_in));
	memset(&fsin, 0, sizeof(struct sockaddr_in));

	sin.sin_family=AF_INET;
	sin.sin_port=htons(port);
	sin.sin_addr.s_addr=htonl(inet_addr(LOCAL));

	if(bind(ns, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		printf("%s ", logtime());
		fflush(stdout);
		perror("bind()");
		return 1;
	}
	printf("%s Bound socket to port %d\n", logtime(), port);

	if(listen(ns, MAXQUEUE) < 0) {
		perror("listen()");
		return 1;
	}

	printf("%s Listening for connections...\n", logtime());
	while(1) {
		/* Set time interval in which to perform zombie checks...
		** We have to do this every time it loops because select()
		** under Linux clears the timeout struct... lame. */
		to.tv_sec = CHECKTIME * 60;
		to.tv_usec = 0;

		/* Clear input */
		FD_ZERO(&input);
		FD_SET(ns, &input);
		if(select(ns + 1, &input, NULL, NULL, &to) > 0) {
			if((rs = accept(ns, (struct sockaddr *)&fsin, &fromlen)) < 0) {
				printf("%s ", logtime());
				fflush(stdout);
				perror("accept()");
				continue;
			}
		} else {
			/* Kill off zombies */
			while((pid = waitpid(0, NULL, WNOHANG)) > 0) {
				printf("%s [%d] Connection closed - purging session\n", logtime(), pid);
				clients--;
			}
			continue;
		}

		if(clients >= MAXCLIENTS) {
			s = rs;
			put("\nSorry, Net Tamagotchi is full right now.\nTry logging in later.\n\n");
			close(rs);
			continue;
		}

		clients++;
		flags = fcntl(ns, F_GETFL);
		flags |= O_NONBLOCK;

		if(fcntl(ns, F_SETFL, flags) < 0) {
			printf("%s ", logtime());
			fflush(stdout);
			perror("fcntl()");
		}

		/* Fork a child to handle the session and wait for it to terminate */
		if((pid=fork()) > 0) {

		/* Resolve remote hostname */
			hp = gethostbyaddr((char *)&fsin.sin_addr, sizeof(struct in_addr), fsin.sin_family);
			if (hp)
				host = hp->h_name;
			else
				host = inet_ntoa(fsin.sin_addr);	
	
			printf("%s [%d] Accepted connection from %s\n", logtime(), pid, host);
			close(rs);
			continue;
		}

		/* Login */
		s = rs;

		if((fd=open(MOTD, O_RDONLY)) > 0)
			putmotd(fd);

		put(INTRO);
		alarm(TIMELIMIT);	/* Set timeout alarm */

		get(buf);
		strncpy(name, buf, MAXNAME);
		if(exist(buf)<0) {
			/* Check username format */
			if(check(name)<0) {
				put("That name is invalid.\n");
				put(STRINGRULE);
				close(s);
				exit(0);
			}
			put("That Tamagotchi doesn't exist. Would you like to create it? ");
			get(buf);
			if(buf[0]!='y' && buf[0]!='Y') {
				put("Fine, but you're missing out!\n");
				close(s);
				exit(0);
			}
			while(1) {
				put("Please choose a password: ");
				get(buf);
	
			/* Check password format validity */
				if(check(buf)==0) break;
				put(STRINGRULE);
			}
			if(new(name, buf) < 0) {
				put(NOACCESS );
				close(s);
				exit(0);
			}
			put("\nNew Tamagotchi \"");
			put(name);
			put("\", created.\n");
			printf("%s Created %s\n", logtime(), name);
		} else {
			put("Tamagotchi found. Please enter password: ");
			get(buf);
			if(checkpass(name, buf)<0) {
				printf("%s Incorrect password for %s\n", logtime(), name);
				put("Password incorrect.\n");
				return 1;
			}
		}

		printf("%s [%d] `%s` logged in\n", logtime(), getpid(), name);
		put("Hi! The time limit for this session is 5 minutes\n");
		status(name, 1);

		while(1) {
			do {
				buf[0]='\0';
				put("> ");
				get(buf);
			} while(strlen(buf)==0);
	
			printf("%s Got command from %s: %s\n", logtime(), name, buf);

			/* parse argument */
			if(strstr(buf, " ")!=NULL) {
				ptr = buf;
				while(isalnum(ptr[0])) ptr++;
				ptr[0] = 0;
				while(!isalnum(ptr[0])) ptr++;
				strncpy(arg, ptr, BUFLEN);
			} else arg[0] = 0;

			if(strstr(arg, " ")!=NULL) {
				ptr = arg;
				while(isalnum(ptr[0])) ptr++;
				ptr[0] = 0;
				while(!isalnum(ptr[0])) ptr++;
			} else ptr = NULL;

			if(exec(buf, arg, ptr, name) < 0) {
				put(BYE);
				close(s);
				return 0;
			}
		}
	}
	return 0;
}
