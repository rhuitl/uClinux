/* tacc.c  TACACS+ PAP authentication client
 * 
 * Copyright 1997-98 by Pawel Krawczyk <kravietz@ceti.com.pl>
 * Portions copyright (c) 1989 Carnegie Mellon University.
 *
 * See http://www.ceti.com.pl/~kravietz/progs/tacacs.html
 * for details.
 *
 */

#include <stdio.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <utmp.h> 
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#ifdef __FreeBSD__
#include "getopt.h"
#include <libutil.h>
#else
#include <getopt.h>
#endif
#include <ctype.h>

#include "tacplus.h"
#include "libtac.h"
#include "magic.h"

/* CONFIGURABLE PARAMETERS */

/* TACACS+ server FQDN or IP address */
#define DEFAULT_SERVER "195.116.211.2"

/* key used to encrypt TACACS+ packets 
 * should be same as key set in TACACS+
 * server configuration 
 */ 
#define DEFAULT_SECRET "dupa-20"

/* Prompt displayed when asking for password */
#define PASSWORD_PROMPT "Password: "

/* if defined, given command will be run after
 * successful authentication and proper wtmp
 * entries will be made 
 */
#define DEFAULT_COMMAND "/usr/sbin/pppd -detach"

/* message that will be displayed to user
 * before starting COMMAND 
 */
#define COMMAND_MESSAGE "Starting PPP\n"

/* timeout for reading password from user (seconds) */
#define GETPASS_TIMEOUT 60

/* end of CONFIGURABLE PARAMETERS */

/* prototypes */
void sighandler(int sig);
void showusage(char *argv0);
unsigned long getservername(char *serv);
#if (defined(__linux__) && ! __GLIBC__ >= 2) || defined(__FreeBSD)
int logwtmp (char *line, char *name, char *host);
#endif
void showusage(char *progname);
void showversion(char *progname);
void authenticate(unsigned long *tac_server, int tac_servers, char *user,
				char *pass, char *tty);
void timeout_handler(int signum);

#define	EXIT_OK		0
#define	EXIT_FAIL	1	/* AAA failure (or server error) */
#define	EXIT_ERR	2	/* local error */

#define USE_SYSTEM	1

/* globals */
char *tac_secret = NULL;
int tac_encryption = 1;
typedef unsigned char flag;
flag quiet = 0;
char *user = NULL; /* global, because of signal handler */

/* command line options */
static struct option long_options[] = {
	/* operation */
	{"authenticate", no_argument, NULL, 'T'},
	{"authorize", no_argument, NULL, 'R'},
	{"account", no_argument, NULL, 'A'},
	{"version", no_argument, NULL, 'V'},
	{"help", no_argument, NULL, 'h'},
	
	/* data */
	{"username", required_argument, NULL, 'u'},
	{"password", required_argument, NULL, 'p'},
	{"server", required_argument, NULL, 's'},
	{"secret", required_argument, NULL, 'k'},
	{"command", required_argument, NULL, 'c'},
	{"exec", required_argument, NULL, 'c'},

	/* modifiers */
	{"quiet", no_argument, NULL, 'q'},
	{"silent", no_argument, NULL, 'q'},
	{"no-wtmp", no_argument, NULL, 'w'},
	{"no-encrypt", no_argument, NULL, 'n'},
	{0, 0, 0, 0}
};

/* command line letters */
char *opt_string="TRAVhu:p:s:k:c:qwn";

int main(int argc, char **argv) {
	char *pass = NULL;
	char *tty;
	char *command = NULL;
	unsigned long tac_server[2];
	int tac_servers = 0;
	int tac_fd;
    short int task_id = 0;
	char buf[40];
#ifndef USE_SYSTEM
	pid_t pid;
#endif
	char *msg;
	struct areply arep;

	/* options */
	flag log_wtmp = 1;
	flag do_author = 0;
	flag do_authen = 0;
	flag do_account = 0;
	flag login_mode = 0;

	/* check argc */
	if(argc < 2) {
		showusage(argv[0]);	
		exit(EXIT_ERR);
	}
	
	/* check for login mode */
	if(argc == 2 && isalpha(*argv[1])) {
		user = argv[1];
		do_author = do_authen = do_account = 1;
		command = DEFAULT_COMMAND;
		login_mode = 1;
	} else {
		int c;
		int opt_index;
		
		while((c=getopt_long(argc, argv, opt_string, 
				long_options, &opt_index)) != EOF) {
			switch(c) {
				case 'T':
					do_authen = 1;
					break;
				case 'R':
					do_author = 1;
					break;
				case 'A':
					do_account = 1;
					break;
				case 'V':
					showversion(argv[0]);
				case 'h':
					showusage(argv[0]);
				case 'u':
					user = optarg;
					break;
				case 'p':
					pass = optarg;
					break;
				case 's': 
					if(tac_servers >= 2) {
						/* allow no more that 2 servers */
						if(!quiet)
						printf("no more than 2 servers allowed: ignoring %s\n",
										optarg);
						break;
					}
					tac_servers++;
					tac_server[tac_servers - 1] = getservername(optarg);
					break;
				case 'k':
					tac_secret = optarg;
					break;
				case 'c':
					command = optarg;
					break;
				case 'q':
					quiet = 1;
					break;
				case 'w':
					log_wtmp = 0;
					break;
				case 'n':
					tac_encryption = 0;
					break;
			}
		}
	}

	/* check available information and set to defaults if needed */
	if(do_authen + do_author + do_account == 0) {
			printf("error: you must specify one of -TRAVh options\n");
			exit(EXIT_ERR);
	}

	if(user == NULL) {
			printf("error: you must specify username.\n");
			exit(EXIT_ERR);
	}

	if(!tac_servers) {
		tac_server[0] = getservername(DEFAULT_SERVER);
		tac_servers++;
	}

	if(tac_secret == NULL)
		tac_secret = DEFAULT_SECRET;
	
	if(pass == NULL) {
		signal(SIGALRM, timeout_handler);
		alarm(GETPASS_TIMEOUT);
		pass = getpass(PASSWORD_PROMPT);
		alarm(0);
		signal(SIGALRM, SIG_DFL);
		if(!strlen(pass))
			exit(EXIT_ERR);
	}

  	tty=ttyname(0);
	if(strncmp(tty, "/dev/", 5) == 0)
		tty += 5;	

	/* open syslog before any TACACS+ calls */
	openlog("tacc", LOG_CONS|LOG_PID, LOG_AUTHPRIV);

	magic_init();
	
	if(do_authen)
			authenticate(tac_server, tac_servers, user, pass, tty);

	if(do_author) {
		/* authorize user */
		struct tac_attrib *attr = NULL;
		tac_add_attrib(&attr, "service", "ppp");
		tac_add_attrib(&attr, "protocol", "lcp");
	
		tac_fd = tac_connect(tac_server, tac_servers);
		tac_author_send(tac_fd, user, tty, attr);
	
		tac_author_read(tac_fd, &arep);
		if(arep.status != AUTHOR_STATUS_PASS_ADD &&
			arep.status != AUTHOR_STATUS_PASS_REPL ) {
				if(!quiet) printf("Authorization FAILED: %s\n", arep.msg);
				exit(EXIT_FAIL);
		} else {
			if(!quiet) printf("Authorization OK: %s\n", arep.msg);
		}
	
		tac_free_attrib(&attr);
	}

	/* we no longer need the password in our address space */
	bzero(pass, strlen(pass));
	pass = NULL;
	
	if(do_account) {
		/* start accounting */
		struct tac_attrib *attr = NULL;
		sprintf(buf, "%lu", time(0));
		tac_add_attrib(&attr, "start_time", buf);
		task_id=(short int) magic();
		sprintf(buf, "%hu", task_id);
		tac_add_attrib(&attr, "task_id", buf);
		tac_add_attrib(&attr, "service", "ppp");
		tac_add_attrib(&attr, "protocol", "lcp");
		
		tac_fd=tac_connect(tac_server, tac_servers);

		tac_account_send(tac_fd, TAC_PLUS_ACCT_FLAG_START, user,
				tty, 0, attr);

		msg = tac_account_read(tac_fd);
		if(msg != NULL) {
			if(!quiet) printf("Accounting: START failed: %s\n", msg);
			syslog(LOG_INFO,"TACACS+ accounting start failed: %s",
									msg);
		} else if(!login_mode && !quiet)
			printf("Accounting: START ok\n");

		close(tac_fd);

		tac_free_attrib(&attr);

	}

	/* log in local utmp */
	if(log_wtmp)
        	logwtmp(tty, user, "dialup");

	if(command != NULL) {
		int ret;

		syslog(LOG_DEBUG, "starting %s for %s", command, user);

		signal(SIGHUP, SIG_IGN);
		signal(SIGTERM, SIG_IGN);
		signal(SIGINT, SIG_IGN);
		signal(SIGCHLD, SIG_IGN);

#ifdef COMMAND_MESSAGE
		printf(COMMAND_MESSAGE);
#endif

#if USE_SYSTEM
		ret = system(command);
		if(ret < 0)
				syslog(LOG_WARNING, "command failed: %m");
		else
				syslog(LOG_NOTICE, "command exit code %u", ret);
#else
		pid=fork();
		
		if(pid == 0) {
		/* child */
			
			execl(DEFAULT_COMMAND, DEFAULT_COMMAND, ARGS, NULL);
			syslog(LOG_ERR, "execl() failed: %m");
			_exit(EXIT_FAIL);
		}

		if(pid < 0) {
		/* error */
			syslog(LOG_ERR, "fork failed: %m");
			exit(EXIT_FAIL);
		}		

		if(pid > 0) {
		/* parent */
			int st, r;

			r=wait(&st);
			/* syslog(LOG_ERR, "wait(): %d", r); */
		}
#endif
	}	
	
	if(do_account) {
		/* stop accounting */
		struct tac_attrib *attr = NULL;
		sprintf(buf, "%lu", time(0));
		tac_add_attrib(&attr, "stop_time", buf);
		sprintf(buf, "%hu", task_id);
		tac_add_attrib(&attr, "task_id", buf);
	
		tac_fd=tac_connect(tac_server, tac_servers);

		tac_account_send(tac_fd, TAC_PLUS_ACCT_FLAG_STOP, user,
			tty, 0, attr);
		msg = tac_account_read(tac_fd);
		if(msg != NULL) {
			if(!quiet) printf("Accounting: STOP failed: %s", msg);
			syslog(LOG_INFO,"TACACS+ accounting stop failed: %s\n",
									msg);
		} else if(!login_mode && !quiet)
			printf("Accounting: STOP ok\n");

		close(tac_fd);

		tac_free_attrib(&attr);
	}

	/* logout from utmp */
	if(log_wtmp)
        	logwtmp(tty, "", "");

	exit(EXIT_OK);	
}


void sighandler(int sig) {
	TACDEBUG((LOG_DEBUG, "caught signal %d", sig));
}

void authenticate(unsigned long *tac_server, int tac_servers, char *user,
				char *pass, char *tty)
{
	int tac_fd;
	char *msg;


	tac_fd=tac_connect(tac_server, tac_servers);
	
	if(tac_fd < 0) {
		if(!quiet) printf("Error connecting to TACACS+ server: %m\n");
		exit(EXIT_ERR);
	}

	/* start authentication */

	if(tac_authen_pap_send(tac_fd, user, pass, tty) < 0) {
		if(!quiet) printf("Error sending query to TACACS+ server\n");
		exit(EXIT_ERR);
	}

	msg=tac_authen_pap_read(tac_fd);
	
	if(msg != NULL) {
		if(!quiet) printf("Authentication FAILED: %s\n", msg);
		syslog(LOG_ERR, "authentication failed for %s: %s", user, msg);
		exit(EXIT_FAIL);
	}

	if(!quiet) printf("Authentication OK\n");
	syslog(LOG_INFO, "authentication OK for %s", user);

	close(tac_fd);
}

void showusage(char *progname) {
	char *a;

	a = rindex(progname, '/');	
	progname = (a == NULL) ? progname : ++a; 

	printf("%s -- simple TACACS+ client and login, version %u.%u.%u\n",
		progname, tac_ver_major, tac_ver_minor, tac_ver_patch);
	printf("Copyright 1997-98 by Pawel Krawczyk <kravietz@ceti.com.pl>\n");
	printf("usage: %s option [option, ...]\n", progname);
	printf("       %s username\n", progname);
	printf("When started with username as the only parameter, %s will use\n", progname);
	printf("compiled-in default values for server address and secret. It will\n");
	printf("also display prompt and read password from standard input.\n");
	printf("Otherwise, the following options are accepted in command line:\n");
	printf(" Action:\n");
	printf("  -T, --authenticate  perform authentication of username and password\n");
	printf("  -R, --authorize     perform authorization for requested service\n");
	printf("  -A, --account       account session beginning and end\n");
	printf("  -h, --help          display this help and exit\n");
	printf("  -V, --version       display version number and exit\n");
	printf(" Data:\n");
	printf("  -u, --username      user's name\n");
	printf("  -p, --password      user's password\n");
	printf("  -s, --server        server's address or FQDN (multiple allowed)\n");
	printf("  -k, --secret        shared secret to encrypt packets\n");
	printf("  -c, --command       command to execute after success in all of\n");
	printf("      --exec           specified actions\n");
	printf(" Modifiers:\n");
	printf("  -q, --quiet         don't display messages to screen (but still\n");
	printf("      --silent         report them via syslog(3))\n");
	printf("  -w, --no-wtmp       don't write records to wtmp(5)\n");
	printf("  -n, --no-encrypt    don't encrypt AAA packets sent to servers\n");

	exit(EXIT_ERR);
}

void showversion(char *progname) {
	char *a;
		
	a = rindex(progname, '/');
	progname = (a == NULL) ? progname : ++a;
	
	printf("%s %u.%u.%u\n",
		       	progname, tac_ver_major, tac_ver_minor, tac_ver_patch);
	exit(EXIT_OK);
}

unsigned long getservername(char *serv) {
	struct in_addr addr;
	struct hostent *h;

	if(inet_aton(serv, &addr) == 0) {
		if((h=gethostbyname(serv)) == NULL) {
			herror("gethostbyname");
		} else {
			bcopy(h->h_addr, (char *)&addr, sizeof(struct in_addr));
			return(addr.s_addr);
		}
	} else 
		return(addr.s_addr);

	return(-1);
}

/*
 * This is logwtmp() taken from sys-linux.c, changed a bit for
 * compatibility with tacc.c
 */

#if (defined(__linux__) && ! __GLIBC__ >= 2) || defined(__FreeBSD)
int logwtmp (char *line, char *name, char *host)
  {
    int    mode;
    int    wtmp;
    struct utmp ut, *utp;
    pid_t  mypid = getpid();
/*
 * Control the 'mesg' function based upon the state of the logon
 * operation. If the user is being 'logged on' then disable the
 * mesg function. When the user 'logs off' then re-enable it.
 */
    mode = (*name != '\0') ? 0600 : 0622;
/*    if (chmod (devnam, mode) < 0)
      {
	syslog (LOG_ERR, "chmod(\"%s\", 0%o): %m", devnam, mode);
      }
*/
/*
 * Update the signon database for users.
 * Christoph Lameter: Copied from poeigl-1.36 Jan 3, 1996
 */
    utmpname(_PATH_UTMP);
    setutent();
    while ((utp = getutent()) && (utp->ut_pid != mypid))
        /* nothing */;

    /* Is this call really necessary? There is another one after the 'put' */
    endutent();
    
    if (utp)
      {
	memcpy(&ut, utp, sizeof(ut));
      }
    else
      {
	/* some gettys/telnetds don't initialize utmp... */
	memset(&ut, 0, sizeof(ut));
      }

    if (ut.ut_id[0] == 0)
      {
	strncpy(ut.ut_id, line + 3, sizeof(ut.ut_id));
      }
	
    strncpy(ut.ut_user, name, sizeof(ut.ut_user));
    strncpy(ut.ut_line, line, sizeof(ut.ut_line));

    time(&ut.ut_time);

    ut.ut_type = USER_PROCESS;
    ut.ut_pid  = mypid;

    /* Insert the host name if one is supplied */
    if (*host)
      {
	strncpy (ut.ut_host, host, sizeof(ut.ut_host));
      }

    /* CL: Makes sure that the logout works */
    if (*host == 0 && *name==0)
      {
	ut.ut_host[0]=0;
      }

    pututline(&ut);
    endutent();
/*
 * Update the wtmp file.
 */
    wtmp = open(_PATH_WTMP, O_APPEND|O_WRONLY);
    if (wtmp >= 0)
      {
	flock(wtmp, LOCK_EX);

    	/* we really should check for error on the write for a full disk! */
	write (wtmp, (char *)&ut, sizeof(ut));
	close (wtmp);

	flock(wtmp, LOCK_UN);
      }
  }
#endif

/*
 * Make a string representation of a network IP address.
 */
char *
ip_ntoa(ipaddr)
u_int32_t ipaddr;
{
    static char b[64];

    ipaddr = ntohl(ipaddr);

    sprintf(b, "%d.%d.%d.%d",
	    (u_char)(ipaddr >> 24),
	    (u_char)(ipaddr >> 16),
	    (u_char)(ipaddr >> 8),
	    (u_char)(ipaddr));
    return b;
}

void timeout_handler(int signum)
{
	syslog(LOG_ERR, "timeout reading password from user %s", user);

}
