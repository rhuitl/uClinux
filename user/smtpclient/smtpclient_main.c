/*   ____  __  _ _____ ____     _ _            _   
**  / ___||  \/ |_   _|  _ \___| (_) ___ _ __ | |_ 
**  \___ \| |\/| || | | |_)/ __| | |/ _ \ '_ \| __|
**   ___) | |  | || | |  _| (__| | |  __/ | | | |_ 
**  |____/|_|  |_||_| |_|  \___|_|_|\___|_| |_|\__|
**   
**  SMTPclient -- simple SMTP client
**
**  This program is a minimal SMTP client that takes an email
**  message body and passes it on to a SMTP server (default is the
**  MTA on the local host). Since it is completely self-supporting,
**  it is especially suitable for use in restricted environments.
**
**  ======================================================================
**
**  Copyright (c) 1997 Ralf S. Engelschall, All rights reserved.
**
**  This program is free software; it may be redistributed and/or modified
**  only under the terms of either the Artistic License or the GNU General
**  Public License, which may be found in the SMTP source distribution.
**  Look at the file COPYING. 
**
**  This program is distributed in the hope that it will be useful, but
**  WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  ======================================================================
**
**  smtpclient_main.c -- program source
**
**  Based on smtp.c as of August 11, 1995 from
**      W.Z. Venema,
**      Eindhoven University of Technology,
**      Department of Mathematics and Computer Science,
**      Den Dolech 2, P.O. Box 513, 5600 MB Eindhoven, The Netherlands.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <syslog.h>
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <pwd.h>

#include "smtpclient_getopt.h"
#include "smtpclient_errno.h"
#include "smtpclient_vers.h"

static char *cc_addr    = 0;
static char *err_addr   = 0;
static char *from_addr  = NULL;
static char *sender_addr  = NULL;
static char *mailhost   = NULL;
static int   mailport   = 25;
static char *reply_addr = 0;
static char *subject    = 0;
static int   mime_style = 0;
static int   verbose    = 0;
static int   usesyslog  = 0;

static FILE *sfp;
static FILE *rfp;

#define dprintf  if (verbose) printf
#define dvprintf if (verbose) vprintf

/* hack for Ultrix */
#ifndef LOG_DAEMON
#define LOG_DAEMON 0
#endif

/*
**  logging support
*/
void log(char *str, ...)
{
    va_list ap;
    char buf[1024];

    va_start(ap, str);
    vsnprintf(buf, 1024, str, ap);
    if (usesyslog)
        syslog(LOG_ERR, "SMTPclient: %s", buf);
    else
        fprintf(stderr, "SMTPclient: %s\n", buf);
    va_end(ap);
    return;
}

/*
**  usage page
*/
void usage(void)
{
    fprintf(stderr, "Usage: smtp [options] recipients ...\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Message Header Options:\n");
    fprintf(stderr, "  -s, --subject=STR      subject line of message\n");
    fprintf(stderr, "  -f, --from=ADDR        address of the sender (From:) \n");
    fprintf(stderr, "  -N, --sender=ADDR      address of the sender (Sender:) \n");
    fprintf(stderr, "  -r, --reply-to=ADDR    address of the sender for replies\n");
    fprintf(stderr, "  -e, --errors-to=ADDR   address to send delivery errors to\n");
    fprintf(stderr, "  -c, --carbon-copy=ADDR address to send copy of message to\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Processing Options:\n");
    fprintf(stderr, "  -S, --smtp-host=HOST   host where MTA can be contacted via SMTP\n");
    fprintf(stderr, "  -P, --smtp-port=NUM    port where MTA can be contacted via SMTP\n");
    fprintf(stderr, "  -H, --src-host=NUM     host name to provide as source of message\n");
    fprintf(stderr, "  -M, --mime-encode      use MIME-style translation to quoted-printable\n");
    fprintf(stderr, "  -L, --use-syslog       log errors to syslog facility instead of stderr\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Giving Feedback:\n");
    fprintf(stderr, "  -v, --verbose          enable verbose logging messages\n");
    fprintf(stderr, "  -V, --version          display version string\n");
    fprintf(stderr, "  -h, --help             display this page\n");
    fprintf(stderr, "\n");
    return;
}

/*
**  version page
*/
void version(void)
{
    fprintf(stdout, "%s\n", SMTPclient_Hello);
    fprintf(stdout, "\n");
    fprintf(stdout, "Copyright (c) 1997 Ralf S. Engelschall, All rights reserved.\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "This program is distributed in the hope that it will be useful,\n");
    fprintf(stdout, "but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
    fprintf(stdout, "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
    fprintf(stdout, "the GNU General Public License for more details.\n");
    fprintf(stdout, "\n");
    return;
}

/*
**  examine message from server 
*/
void get_response(void)
{
    char buf[BUFSIZ];

    while (fgets(buf, sizeof(buf), rfp)) {
        buf[strlen(buf)-1] = 0;
        dprintf("%s --> %s\n", mailhost, buf);
        if (!isdigit(buf[0]) || buf[0] > '3') {
            log("unexpected reply: %s", buf);
            exit(1);
        }
        if (buf[3] != '-')
            break;
    }
    return;
}

/*
**  say something to server and check the response
*/
void chat(char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(sfp, fmt, ap);
    va_end(ap);
  
    va_start(ap, fmt);
    dprintf("%s <-- ", mailhost);
    dvprintf(fmt, ap);
    va_end(ap);

    fflush(sfp);
    get_response();
}

/*
**  transform to MIME-style quoted printable
**
**  Extracted from the METAMAIL version 2.7 source code (codes.c)
**  and modified to emit \r\n at line boundaries.
*/

static char basis_hex[] = "0123456789ABCDEF";

void toqp(FILE *infile, FILE *outfile)
{
    int c;
    int ct = 0;
    int prevc = 255;

    while ((c = getc(infile)) != EOF) {
        if (   (c < 32 && (c != '\n' && c != '\t'))
            || (c == '=')
            || (c >= 127)
            || (ct == 0 && c == '.')               ) {
        putc('=', outfile);
        putc(basis_hex[c >> 4], outfile);
        putc(basis_hex[c & 0xF], outfile);
        ct += 3;
        prevc = 'A'; /* close enough */
    }
    else if (c == '\n') {
        if (prevc == ' ' || prevc == '\t') {
	    putc('=', outfile);  /* soft & hard lines */
	    putc(c, outfile);
	    fflush(outfile);
        }
        putc(c, outfile);
	fflush(outfile);
        ct = 0;
        prevc = c;
    } 
    else {
        if (c == 'F' && prevc == '\n') {
        /*
         * HORRIBLE but clever hack suggested by MTR for
         * sendmail-avoidance
         */
        c = getc(infile);
        if (c == 'r') {
            c = getc(infile);
            if (c == 'o') {
            c = getc(infile);
            if (c == 'm') {
                c = getc(infile);
                if (c == ' ') {
                /* This is the case we are looking for */
                fputs("=46rom", outfile);
                ct += 6;
                } else {
                fputs("From", outfile);
                ct += 4;
                }
            } else {
                fputs("Fro", outfile);
                ct += 3;
            }
            } 
            else {
            fputs("Fr", outfile);
            ct += 2;
            }
        }
        else {
            putc('F', outfile);
            ++ct;
        }
        ungetc(c, infile);
        prevc = 'x'; /* close enough -- printable */
        } 
        else { 
        putc(c, outfile);
        ++ct;
        prevc = c;
        }
    }
    if (ct > 72) {
        putc('=', outfile);
        putc('\r', outfile); 
        putc('\n', outfile);
	fflush(outfile);
        ct = 0;
        prevc = '\n';
    }
    }
    if (ct) {
    putc('=', outfile);
    putc('\r', outfile); 
    putc('\n', outfile);
    fflush(outfile);
    }
    return;
}


/*
**  main procedure
*/

struct option options[] = {
    { "subject",      1, NULL, 's' },
    { "from",         1, NULL, 'f' },
    { "sender",       1, NULL, 'N' },
    { "replay-to",    1, NULL, 'r' },
    { "errors-to",    1, NULL, 'e' },
    { "carbon-copy",  1, NULL, 'c' },
    { "smtp-host",    1, NULL, 'S' },
    { "smtp-port",    1, NULL, 'P' },
    { "src-host",     1, NULL, 'H' },
    { "mime-encode",  0, NULL, 'M' },
    { "use-syslog",   0, NULL, 'L' },
    { "verbose",      0, NULL, 'v' },
    { "version",      0, NULL, 'V' },
    { "help",         0, NULL, 'h' }
};

int main(int argc, char **argv)
{
    static char buf[BUFSIZ];
    static char my_name[BUFSIZ];
    struct sockaddr_in sin;
    struct hostent *hp;
    struct servent *sp;
    int c;
    int s;
    int r;
    int i;
    struct passwd *pwd;
    char *cp;
    char *src_host = NULL;
    int cache_in = 0;
    char *line_cache = NULL;

    /*
     *  Parse options
     */
    while ((c = getopt_long(argc, argv, ":H:s:f:r:e:c:S:P:MLvVhRN:", options, NULL)) != EOF) {
        switch (c) {
	    case 'H':
		src_host = optarg;
		break;
            case 's':
                subject = optarg;
                break;
            case 'N':
                sender_addr = optarg;
                break;
            case 'f':
                from_addr = optarg;
                break;
            case 'r':
                reply_addr = optarg;
                break;
            case 'e':
                err_addr = optarg;
                break;
            case 'c':
                cc_addr = optarg;
                break;
            case 'S':
                mailhost = optarg;
                break;
            case 'P':
                mailport = atoi(optarg);
                break;
            case 'M':
                mime_style = 1;
                break;
            case 'L':
                usesyslog = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'V':
                version();
                exit(0);
            case 'h':
                usage();
                exit(0);
	    case 'R':
		cache_in = 1;
		break;
            default:
                fprintf(stderr, "SMTP: invalid option `%c'\n", optopt);
                fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
                exit(1);
        }
    }
    if (argc == optind) {
        fprintf(stderr, "SMTP: wrong number of arguments\n");
        fprintf(stderr, "Try `%s --help' for more information.\n", argv[0]);
        exit(1);
    }

    if (cache_in) {
	    int sz = 10000;
	    int pos = 0;
	    void safecpy(const char *p) {
		    int l = strlen(p);
		    if (pos+l >= sz) {
			    sz += 4000;
			    line_cache = realloc(line_cache, sz*sizeof(char));
		    }
		    strcpy(line_cache+pos, p);
		    pos += l;
	    }
	    line_cache = malloc(sz * sizeof(char));
            while (fgets(buf, sizeof(buf), stdin)) {
        	buf[strlen(buf)-1] = 0;
        	if (strcmp(buf, ".") == 0) { /* quote alone dots */
			safecpy("..\r\n");
        	} else { /* pass thru mode */
			safecpy(buf);
			safecpy("\r\n");
        	}
            }
    }

    /* 
     *  Go away when something gets stuck.
     */
    alarm(60);

    /*  
     *  Open Syslog facility
     */
    if (usesyslog)
        openlog(argv[0], LOG_PID, LOG_DAEMON);

    /*
     *  Determine SMTP server
     */
    if (mailhost == NULL) {
        if ((cp = getenv("SMTPSERVER")) != NULL)
            mailhost = cp;
        else
            mailhost = "localhost";
    }

    /*
     *  Find out my own host name for HELO; 
     *  if possible, get the FQDN.
     */
    if (src_host == NULL) {
	if (gethostname(my_name, sizeof(my_name) - 1) < 0) {
	log("gethostname: %s", errorstr(errno));
	exit(1);
	}
	if ((hp = gethostbyname(my_name)) == NULL) {
	log("%s: unknown host\n", my_name);
	exit(1);
	}
	strcpy(my_name, hp->h_name);
    } else
	strcpy(my_name, src_host);

    /*
     *  Determine from address.
     */
    if (from_addr == NULL) {
        if ((pwd = getpwuid(getuid())) == 0) {
            snprintf(buf, BUFSIZ, "userid-%d@%s", getuid(), my_name);
        } else {
            snprintf(buf, BUFSIZ, "%s@%s", pwd->pw_name, my_name);
        }
        from_addr = strdup(buf);
    }

    /*
     *  Connect to smtp daemon on mailhost.
     */
    if ((hp = gethostbyname(mailhost)) == NULL) {
        log("%s: unknown host\n", mailhost);
        exit(1);
    }
    if (hp->h_addrtype != AF_INET) {
        log("unknown address family: %d", hp->h_addrtype);
        exit(1);
    }
    memset((char *)&sin, 0, sizeof(sin));
    memcpy((char *)&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(mailport);
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log("socket: %s", errorstr(errno));
        exit(1);
    }
    if (connect(s, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        log("connect: %s", errorstr(errno));
        exit(1);
    }
    if ((r = dup(s)) < 0) {
        log("dup: %s", errorstr(errno));
        exit(1);
    }
    if ((sfp = fdopen(s, "w")) == 0) {
        log("fdopen: %s", errorstr(errno));
        exit(1);
    }
    if ((rfp = fdopen(r, "r")) == 0) {
        log("fdopen: %s", errorstr(errno));
        exit(1);
    }

    /* 
     *  Give out SMTP headers.
     */
    get_response(); /* banner */
    chat("HELO %s\r\n", my_name);
    chat("MAIL FROM: <%s>\r\n", from_addr);
    for (i = optind; i < argc; i++)
        chat("RCPT TO: <%s>\r\n", argv[i]);
    if (cc_addr)
        chat("RCPT TO: <%s>\r\n", cc_addr);
    chat("DATA\r\n");

    /* 
     *  Give out Message header. 
     */
    fprintf(sfp, "From: %s\r\n", from_addr);
    if (subject)
        fprintf(sfp, "Subject: %s\r\n", subject);

    if (reply_addr)
        fprintf(sfp, "Reply-To: %s\r\n", reply_addr);
    if (err_addr)
        fprintf(sfp, "Errors-To: %s\r\n", err_addr);

    if (sender_addr) {
        fprintf(sfp, "Sender: %s\r\n", sender_addr);
    } else if ((pwd = getpwuid(getuid())) == 0) {
        fprintf(sfp, "Sender: userid-%d@%s\r\n", getuid(), my_name);
    } else {
        fprintf(sfp, "Sender: %s@%s\r\n", pwd->pw_name, my_name);
    }

    fprintf(sfp, "To: %s", argv[optind]);
    for (i = optind + 1; i < argc; i++)
        fprintf(sfp, ",%s", argv[i]);
    fprintf(sfp, "\r\n");
    if (cc_addr)
        fprintf(sfp, "Cc: %s\r\n", cc_addr);

    if (mime_style) {
        fprintf(sfp, "MIME-Version: 1.0\r\n");
        fprintf(sfp, "Content-Type: text/plain; charset=ISO-8859-1\r\n");
        fprintf(sfp, "Content-Transfer-Encoding: quoted-printable\r\n");
    }

    fprintf(sfp, "\r\n");
    fflush(sfp);

    /* 
     *  Give out Message body.
     */
    if (cache_in) {
	   fputs(line_cache, sfp);
	   fflush(sfp);
    } else if (mime_style) {
        toqp(stdin, sfp);
    } else {
        while (fgets(buf, sizeof(buf), stdin)) {
            buf[strlen(buf)-1] = 0;
            if (strcmp(buf, ".") == 0) { /* quote alone dots */
                fprintf(sfp, "..\r\n");
            } else { /* pass thru mode */
                fprintf(sfp, "%s\r\n", buf);
            }
	    fflush(sfp);
        }
    }

    /* 
     *  Give out SMTP end.
     */
    chat(".\r\n");
    chat("QUIT\r\n");

    /* 
     *  Die gracefully ...
     */
    exit(0);
}

/*EOF*/
