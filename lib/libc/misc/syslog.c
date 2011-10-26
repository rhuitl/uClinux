#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

/* Use this to allow/disallow network syslog support */
#define NETSYSLOG 1

#ifdef NETSYSLOG
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>

static void opennetlog(void);
#endif

#define DATESYSLOG 1

#ifdef DATESYSLOG
#include <time.h>
#endif

#define	LOGFILE		"/var/log/syslog"
#define	CONFFILE	"/etc/config/config"

/*
 *	you can change the max syslog size here or in the config
 *	file (NETSYSLOG) as syslog_maxsize
 */

static int	syslog_maxsize = 16384; /* 16K of syslog before rotate */
static int	syslog_sfd = -1;
static int	syslog_net = 0;
static char	*syslog_ident = (char *) NULL;


void syslog(int prio, const char *form, ...)
{
	va_list		ptr;
	char		buf[128], *sp, *ep;
	int			fd;
	struct stat	st;

	if ((fd = open(LOGFILE, O_CREAT | O_WRONLY | O_APPEND, 0600)) == -1)
		return;
	
	sp = &buf[0];
	ep = sp + sizeof(buf);

#ifdef DATESYSLOG
{
	time_t tm;
	time(&tm);
	sp += snprintf(sp, ep - sp, "%s", ctime(&tm));
	/* remove the year off the end */
	while (sp > &buf[0] && *(sp-1) != ' ')
		sp--;
}
#endif

	if (syslog_ident)
		sp += snprintf(sp, ep - sp, "%s: ", syslog_ident);
	else
		sp += snprintf(sp, ep - sp, "[%d]: ", getpid());
	va_start(ptr, form);
	sp += vsnprintf(sp, ep - sp, form, ptr);
	va_end(ptr);

	/*
	 * 'vsnprint' returns the actual number of characters _needed_ for the
	 * print, not the number actually written into the buffer. Check 'sp'
	 * to make sure it wasn't advanced past the end of the buffer, less 2
	 * for a trailing '\n' and a NUL terminator.
	 */
	if (sp > (ep - 2))
		sp = ep - 2;

	if (*(sp - 1) != '\n')
		sp += snprintf(sp, ep - sp, "\n");
	write(fd, buf, sp - buf);
	close(fd);

#ifdef NETSYSLOG
	if (syslog_net == 0 && syslog_sfd == -1)
		opennetlog();
	if (syslog_sfd >= 0)
		send(syslog_sfd, buf, (sp - buf), 0);
#endif

if (0) {
/*
 *	hack the output out the console device
 */
	int fd;
	if ((fd = open("/dev/ttyS0", O_WRONLY)) != -1) {
		write(fd, buf, sp - buf);
		tcdrain(fd);
		close(fd);
	}
}

/*
 *	a rather lame attempt at preventing 2 processes from deciding
 *	to rotate the syslog file, thus losing all the syslog.
 */
	if (stat(LOGFILE, &st) != -1 && st.st_size >= syslog_maxsize) {
		snprintf(buf, sizeof(buf), "%s.old", LOGFILE);
		unlink(buf);
		link(LOGFILE, buf);
		unlink(LOGFILE);
	}
}


#ifdef NETSYSLOG

static void opennetlog(void)
{
	struct hostent		*hp;
	struct sockaddr_in	sin;
	char			*whitespace = " 	";
	FILE			*fp;
	char			line[80], *sp;
	char			*ipstr = NULL, *portstr = NULL;

	syslog_net = 1; /* we have tried a opennetlog at least once */

	/* Find syslog machine address and port */
	if ((fp = fopen(CONFFILE, "r")) == (FILE *) NULL)
		return;

	while (fgets(line, sizeof(line), fp) != NULL) {
		if ((sp = strchr(line, '\n')) != NULL)
			*sp = '\0';
		if (strncmp(line, "syslog_maxsize", 14) == 0)
			continue;
		if (strncmp(line, "syslog", 6) == 0) {
			sp = &line[6];
			strsep(&sp, whitespace);
			ipstr = strsep(&sp, whitespace);
			portstr = strsep(&sp, whitespace);
			break;
		}
	}

	fclose(fp);
	
	if (ipstr == NULL)
		return;
	if (portstr == NULL)
		portstr = "514";

	sin.sin_family = AF_INET;
	sin.sin_port = htons(atoi(portstr));
	sin.sin_addr.s_addr = inet_addr(ipstr);
	if (sin.sin_addr.s_addr == -1) {
		if ((hp = gethostbyname(ipstr))) {
			sin.sin_family = hp->h_addrtype;
			memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
		}
	}


	/* Open socket to remote machine for sysloging */
	if ((syslog_sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return;
	}

	if (connect(syslog_sfd, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
		close(syslog_sfd);
		syslog_sfd = -1;
	}
}

#endif /* NETSYSLOG */


void openlog(const char *ident, int i, int j)
{
	FILE *fp;
	char line[80];

	if (syslog_ident) {
		free(syslog_ident);
		syslog_ident = NULL;
	}
	if (ident)
		syslog_ident = strdup(ident);

#ifdef NETSYSLOG
	opennetlog();
#endif

        /* Read maximum system log file size from /etc/config. */
	if ((fp = fopen(CONFFILE, "r")) == (FILE *) NULL)
		return;

	while (fgets(line, sizeof(line), fp) != NULL) {
		if (strncmp(line, "syslog_maxsize", 14) == 0) {
			if (atoi(&line[14]) > 0)
				syslog_maxsize = atoi(&line[14]);
			break;
		}
	}

	fclose(fp);
}


void closelog(void)
{
#ifdef NETSYSLOG
	syslog_net = 0;
	close(syslog_sfd);
#endif
	if (syslog_ident) {
		free(syslog_ident);
		syslog_ident = NULL;
	}
}


int setlogmask(int i)
{
	/* Should really implement this :-) */
}

