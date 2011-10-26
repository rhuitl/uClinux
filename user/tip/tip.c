/*****************************************************************************/

/*
 *	tip.c -- simple tip/cu program.
 *
 *	(C) Copyright 1999-2002, Greg Ungerer (gerg@snapgear.com)
 *	(C) Copyright 2002, SnapGear Inc (www.snapgear.com)
 *
 *	Modified 5 May 2000, Rick Stevenson.
 *		Added -f option to pass XON/XOFF characters through
 *		to remote end.
 *
 *	Modified 020131, Heiko Degenhardt (heiko.degenhardt@sentec-elektronik.de)
 *		- Added signal handler to restore the termios
 *		- Introduced SaveRemoteTermIOs/RestoreRemoteTermIOs to
 *		  correctly leave the remote side.
 *		- Introduced a global var that holds the file pointer
 *		  (FIXME: Don't know if a global var is the right thing!)
 *
 *  Modified 2003/04/20 David McCullough <davidm@snapgear.com>
 *      added file download option
 *
 *  Modified 2004/01/21 David McCullough <davidm@snapgear.com>
 *      connect to IP:PORT instead of serial port
 *
 *  Modified 2004/06/28 David McCullough <davidm@snapgear.com>
 *      add ~b (send break) escape code
 *
 *  Modified 2004/08/16 Peter Hunt <pchunt@snapgear.com>
 *      -l can now take a relative device path from "/dev/" as well (like cu). 
 */

/*****************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/termios.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef EMBED
#include <sys/select.h>
#endif

/*****************************************************************************/

char *version = "1.1.0";

/*****************************************************************************/

/*
 *	Define some parity flags, internal use only.
 */
#define	PARITY_NONE	0
#define	PARITY_EVEN	1
#define	PARITY_ODD	2

/*
 *	Default port settings.
 */
int		clocal;
int		hardware;
int		software;
int		passflow;
int		parity = PARITY_NONE;
int		databits = 8;
int		twostopb;
unsigned int	baud = 9600;
unsigned short	tcpport;

int		translate;
int		ocasemode, icasemode;

char		*devname;
char		*filename;
char		*capfile;
int		verbose = 1;
int		net_connection = 0;
int		gotdevice;
int		ifd, ofd;
int		rfd, cfd;

/*
 *	Working termios settings.
 */
struct termios	savetio_local;
struct termios	savetio_remote;

/*
 *	Signal handling.
 */
struct sigaction	sact;

/*
 *	Temporary buffer to use when working.
 */
unsigned char	ibuf[512];
unsigned char	obuf[1024];

/*****************************************************************************/

/*
 *	Baud rate table for baud rate conversions.
 */
typedef struct baudmap {
	unsigned int	baud;
	unsigned int	flag;
} baudmap_t;


struct baudmap	baudtable[] = {
	{ 0, B0 },
	{ 50, B50 },
	{ 75, B75 },
	{ 110, B110 },
	{ 134, B134 },
	{ 150, B150 },
	{ 200, B200 },
	{ 300, B300 },
	{ 600, B600 },
	{ 1200, B1200 },
	{ 1800, B1800 },
	{ 2400, B2400 },
	{ 4800, B4800 },
	{ 9600, B9600 },
	{ 19200, B19200 },
	{ 38400, B38400 },
	{ 57600, B57600 },
	{ 115200, B115200 },
	{ 230400, B230400 },
	{ 460800, B460800 }
};

#define	NRBAUDS		(sizeof(baudtable) / sizeof(struct baudmap))

/*****************************************************************************/

/*
 *	Verify that the supplied baud rate is valid.
 */

int baud2flag(unsigned int speed)
{
	int	i;

	for (i = 0; (i < NRBAUDS); i++) {
		if (speed == baudtable[i].baud)
			return(baudtable[i].flag);
	}
	return(-1);
}

/*****************************************************************************/

void restorelocaltermios(void)
{
	if (tcsetattr(1, TCSAFLUSH, &savetio_local) < 0) {
		fprintf(stderr, "ERROR: local tcsetattr(TCSAFLUSH) failed, "
			"errno=%d\n", errno);
	}
}

/*****************************************************************************/

void savelocaltermios(void)
{
	if (tcgetattr(1, &savetio_local) < 0) {
		fprintf(stderr, "ERROR: local tcgetattr() failed, errno=%d\n",
			errno);
		exit(0);
	}
}

/*****************************************************************************/

void restoreremotetermios(void)
{
	/*
	 *	This can fail if remote hung up, don't check return status.
	 */
	tcsetattr(rfd, TCSAFLUSH, &savetio_remote);
}

/*****************************************************************************/

int saveremotetermios(void)
{
	if (tcgetattr(rfd, &savetio_remote) < 0) {
		fprintf(stderr, "ERROR: remote tcgetattr() failed, errno=%d\n",
			errno);
		return(0);
	}
	return(1);
}

/*****************************************************************************/

/*
 *	Set local port to raw mode, no input mappings.
 */

int setlocaltermios()
{
	struct termios	tio;

	if (tcgetattr(1, &tio) < 0) {
		fprintf(stderr, "ERROR: local tcgetattr() failed, errno=%d\n",
			errno);
		exit(1);
	}

	if (passflow)
		tio.c_iflag &= ~(ICRNL|IXON);
	else
		tio.c_iflag &= ~ICRNL;
	tio.c_lflag = 0;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;

	if (tcsetattr(1, TCSAFLUSH, &tio) < 0) {
		fprintf(stderr, "ERROR: local tcsetattr(TCSAFLUSH) failed, "
			"errno=%d\n", errno);
		exit(1);
	}
	return(0);
}

/*****************************************************************************/

/*
 *	Set up remote (connect) port termio settings according to
 *	user specification.
 */

int setremotetermios()
{
	struct termios	tio;

	memset(&tio, 0, sizeof(tio));
	tio.c_cflag = CREAD | HUPCL | baud2flag(baud);

	if (clocal)
		tio.c_cflag |= CLOCAL;

	switch (parity) {
	case PARITY_ODD:	tio.c_cflag |= PARENB | PARODD; break;
	case PARITY_EVEN:	tio.c_cflag |= PARENB; break;
	default:		break;
	}

	switch (databits) {
	case 5:		tio.c_cflag |= CS5; break;
	case 6:		tio.c_cflag |= CS6; break;
	case 7:		tio.c_cflag |= CS7; break;
	default:	tio.c_cflag |= CS8; break;
	}
	
	if (twostopb)
		tio.c_cflag |= CSTOPB;

	if (software)
		tio.c_iflag |= IXON | IXOFF;
	if (hardware)
		tio.c_cflag |= CRTSCTS;

	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;

	if (tcsetattr(rfd, TCSAFLUSH, &tio) < 0) {
		fprintf(stderr, "ERROR: remote tcsetattr(TCSAFLUSH) failed, "
			"errno=%d\n", errno);
		return(0);
	}
	return(1);
}

/*****************************************************************************/

void sighandler(int signal)
{
	if (tcpport) {
		close(ifd);
		close(ofd);
	} else {
		printf("\n\nGot signal %d!\n", signal);
		printf("Cleaning up...");
		restorelocaltermios();
		restoreremotetermios();
		printf("Done\n");
	}
	close(rfd);
	exit(1);
}

/*****************************************************************************/

/*
 *	Code to support 5bit translation to ascii.
 *	Whacky 5 bit system used on some older teletype equipment.
 */
unsigned char	ascii2code[128] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a,
	0x00, 0x00, 0x08, 0x00, 0x00, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x85, 0x96, 0x00, 0x94,
	0x97, 0x89, 0x00, 0x91, 0x86, 0x98, 0x87, 0x97,
	0x8d, 0x9d, 0x99, 0x90, 0x8a, 0x81, 0x95, 0x9c,
	0x8c, 0x83, 0x8e, 0x00, 0x00, 0x8f, 0x00, 0x93,
	0x8b, 0x18, 0x13, 0x0e, 0x12, 0x10, 0x16, 0x0a,
	0x05, 0x0c, 0x1a, 0x1e, 0x09, 0x07, 0x06, 0x03,
	0x0d, 0x1d, 0x0a, 0x14, 0x01, 0x1c, 0x0f, 0x19,
	0x17, 0x15, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x18, 0x13, 0x0e, 0x12, 0x10, 0x16, 0x0a,
	0x05, 0x0c, 0x1a, 0x1e, 0x09, 0x07, 0x06, 0x03,
	0x0d, 0x1d, 0x0a, 0x14, 0x01, 0x1c, 0x0f, 0x19,
	0x17, 0x15, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
};

unsigned char	lower2ascii[32] = {
	0x00, 0x74, 0x0d, 0x6f, 0x20, 0x68, 0x6e, 0x6d,
	0x0a, 0x6c, 0x72, 0x67, 0x69, 0x70, 0x63, 0x76,
	0x65, 0x7a, 0x64, 0x62, 0x73, 0x79, 0x66, 0x78,
	0x61, 0x77, 0x6a, 0x80, 0x75, 0x71, 0x6b, 0x80,
};

unsigned char	upper2ascii[32] = {
	0x00, 0x35, 0x0d, 0x39, 0x20, 0x24, 0x2c, 0x2e,
	0x0a, 0x29, 0x34, 0x40, 0x38, 0x30, 0x3a, 0x3d,
	0x33, 0x2b, 0x00, 0x3f, 0x27, 0x36, 0x25, 0x2f,
	0x2d, 0x32, 0x07, 0x80, 0x37, 0x31, 0x28, 0x80,
};

int translateread(unsigned char *ip, unsigned char *op, int n)
{
	unsigned char	*sop, c;
	int		i;

	for (sop = op, i = 0; (i < n); i++) {
		c = *ip++;
		if (c == 0x1f)
			icasemode = 0;
		else if (c == 0x1b)
			icasemode = 1;
		else
			c = (icasemode) ? upper2ascii[c] : lower2ascii[c];
		*op++ = c;
	}
	return(op - sop);
}

int translatewrite(unsigned char *ip, unsigned char *op, int n)
{
	unsigned char	*sop, c;
	int		i;

	for (sop = op, i = 0; (i < n); i++) {
		c = *ip++;
		c = ascii2code[c & 0x7f];
		if (ocasemode && ((c & 0x80) == 0)) {
			*op++ = 0x1f;
			ocasemode = 0;
		}
		if ((ocasemode == 0) && (c & 0x80)) {
			*op++ = 0x1b;
			ocasemode = 1;
		}
		*op++ = (c & 0x1f);
	}
	return(op - sop);
}

/*****************************************************************************/

/*
 *  Send the file named on the command line to the remote end
 */

void send_file()
{
	int fd, n, rc;
	char	*bp;
	fd_set	infds, outfds;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "ERROR: open(%s) failed, errno=%d\n", filename, errno);
		return;
	}

	while ((n = read(fd, ibuf, sizeof(ibuf))) > 0) {
		bp = ibuf;
		while (n > 0) {
			FD_ZERO(&infds);
			FD_ZERO(&outfds);
			FD_SET(rfd, &infds);
			FD_SET(rfd, &outfds);
			if (select(rfd + 1, &infds, &outfds, NULL, NULL) <= 0)
				break;
			if (FD_ISSET(rfd, &infds)) {
				rc = read(rfd, obuf, sizeof(obuf));
				if (rc <= 0) {
					close(fd);
					return;
				}
				write(ofd, obuf, rc);
			}
			if (FD_ISSET(rfd, &outfds)) {
				rc = write(rfd, bp, 1);
				if (rc <= 0)
					break;
				n -= rc;
				bp += rc;
			}
		}
	}

	close(fd);
}

/*****************************************************************************/

/*
 *	Do the connection session. Pass data between local and remote
 *	ports.
 */

int loopit()
{
	fd_set	infds;
	char	*bp;
	int	maxfd, n;
	int	partialescape = 0;

	maxfd = ifd;
	if (maxfd < rfd)
		maxfd = rfd;
	maxfd++;

	for (;;) {
		FD_ZERO(&infds);
		FD_SET(ifd, &infds);
		FD_SET(rfd, &infds);

		if (select(maxfd, &infds, NULL, NULL, NULL) < 0) {
			fprintf(stderr, "ERROR: select() failed, errno=%d\n",
				errno);
			exit(1);
		}

		if (FD_ISSET(rfd, &infds)) {
			bp = ibuf;
			if ((n = read(rfd, ibuf, sizeof(ibuf))) < 0) {
				fprintf(stderr, "ERROR: read(fd=%d) failed, "
					"errno=%d\n", rfd, errno);
				exit(1);
			}
			if (n == 0)
				break;
			if (translate) {
				n = translateread(ibuf, obuf, n);
				bp = obuf;
			}
			if (write(ofd, bp, n) < 0) {
				fprintf(stderr, "ERROR: write(fd=%d) failed, "
					"errno=%d\n", 1, errno);
				exit(1);
			}
			if (cfd > 0)
				write(cfd, bp, n);
		}

		if (FD_ISSET(ifd, &infds)) {
			bp = ibuf;
			if ((n = read(ifd, ibuf, sizeof(ibuf))) < 0) {
				fprintf(stderr, "ERROR: read(fd=%d) failed, "
					"errno=%d\n", 1, errno);
				exit(1);
			}

			if (n == 0)
				break;
#ifdef ALTERNATE
			if ((n == 1) && (*bp == 26))
				break;
#endif
			if (partialescape) {
				partialescape = 0;
				if (*bp == '.')
					break;
				else if (*bp == 's') {
					send_file();
					continue;
				} else if (*bp == 'b') {
					tcsendbreak(rfd, 0);
					continue;
				}
			} else {
				partialescape = ((n == 1) && (*bp == '~')) ? 1 : 0;
				if (partialescape)
					continue;
			}

			if (translate) {
				n = translatewrite(ibuf, obuf, n);
				bp = obuf;
			}


			if (write(rfd, bp, n) < 0) {
				fprintf(stderr, "ERROR: write(rfd=%d) failed, "
					"errno=%d\n", rfd, errno);
				exit(1);
			}
		}
	}
	return (0);
}

/*****************************************************************************/

void opensoc(void)
{
	struct sockaddr_in	s;
	struct sockaddr		p;
	socklen_t		plen;
	int			fd;

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "ERROR: failed to create socket(), "
			"errno=%d\n", errno);
		exit(1);
	}
	memset(&s, 0, sizeof(s));
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = htonl(INADDR_ANY);
	s.sin_port = htons(tcpport);
	if (bind(fd, (struct sockaddr *) &s, sizeof(s)) < 0) {
		fprintf(stderr, "ERROR: failed to bind() socket, "
			"errno=%d\n", errno);
		exit(1);
	}
	if (listen(fd, 1) < 0) {
		fprintf(stderr, "ERROR: failed to listen() socket, "
			"errno=%d\n", errno);
		exit(1);
	}
	plen = sizeof(p);
	if ((ifd = accept(fd, &p, &plen)) < 0) {
		fprintf(stderr, "ERROR: failed to accept() on socket, "
			"errno=%d\n", errno);
		exit(1);
	}
	close(fd);
	ofd = ifd;
}

/*****************************************************************************/

void usage(FILE *fp, int rc)
{
	fprintf(fp, "Usage: tip [-?heonxrwcqt125678] [-s speed] [-w file] "
		"[-p tcpport] [-l device] [device]\n\n"
		"\t-h?\tthis help\n"
		"\t-q\tquiet mode (no helpful messages)\n"
		"\t-1\t1 stop bits (default)\n"
		"\t-2\t2 stop bits\n"
		"\t-5\t5 data bits\n"
		"\t-6\t6 data bits\n"
		"\t-7\t7 data bits\n"
		"\t-8\t8 data bits (default)\n"
		"\t-e\teven parity\n"
		"\t-o\todd parity\n"
		"\t-n\tno parity (default)\n"
		"\t-c\tuse clocal mode (no disconnect)\n"
		"\t-t\ttranslate 5 bit codes to ascii\n"
		"\t-x\tuse software flow (xon/xoff)\n"
		"\t-r\tuse hardware flow (rts/cts)\n"
		"\t-f\tpass xon/xoff flow control to remote\n"
		"\t-s\tbaud rate (default 9600)\n"
		"\t-w\tcapture remote output to local file\n"
		"\t-p\tbind to tcpport instead of using stdin/stdout\n"
		"\t-l\tdevice to use\n"
		"\t-d\tdownload file name\n");
	exit(rc);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	struct stat 	statbuf;
	int		c;
	size_t		len;
	char 		*path = NULL;

	ifd = 0;
	ofd = 1;
	gotdevice = 0;

	while ((c = getopt(argc, argv, "?heonxrcqtf125678w:s:p:l:d:")) > 0) {
		switch (c) {
		case 'v':
			printf("%s: version %s\n", argv[0], version);
			exit(0);
		case '1':
			twostopb = 0;
			break;
		case '2':
			twostopb = 1;
			break;
		case '5':
			databits = 5;
			break;
		case '6':
			databits = 6;
			break;
		case '7':
			databits = 7;
			break;
		case '8':
			databits = 8;
			break;
		case 't':
			translate++;
			break;
		case 'r':
			hardware++;
			break;
		case 'x':
			software++;
			break;
		case 'f':
			passflow++;
			break;
		case 'o':
			parity = PARITY_ODD;
			break;
		case 'e':
			parity = PARITY_EVEN;
			break;
		case 'n':
			parity = PARITY_NONE;
			break;
		case 's':
			baud = atoi(optarg);
			if (baud2flag(baud) < 0) {
				fprintf(stderr,
					"ERROR: baud speed specified %d\n",
					baud);
				exit(1);
			}
			break;
		case 'c':
			clocal++;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'w':
			capfile = optarg;
			break;
		case 'l':
			gotdevice++;
			devname = optarg;
			break;
		case 'p':
			tcpport = atoi(optarg);
			break;
		case 'd':
			filename = optarg;
			break;
		case 'h':
		case '?':
			usage(stdout, 0);
			break;
		default:
			fprintf(stderr, "ERROR: unkown option '%c'\n", c);
			usage(stderr, 1);
			break;
		}
	}

	if ((optind < argc) && (gotdevice == 0)) {
		gotdevice++;
		devname = argv[optind++];
	}

	if (gotdevice == 0) {
		fprintf(stderr, "ERROR: no device specified\n");
		usage(stderr, 1);
	}
	if (optind < argc) {
		fprintf(stderr, "ERROR: too many arguments\n");
		usage(stderr, 1);
	}

	/*
	 *	Check device is real, and open it.  If it is format IP:port
	 *	then it is a TCP connection to IP, port N.
	 */
	if (strchr(devname, ':')) {
		struct sockaddr_in	s;
		char			*port;
		
		port = strchr(devname, ':');
		*port++ = '\0';
		if ((rfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
			fprintf(stderr, "ERROR: failed to create socket(), "
				"errno=%d\n", errno);
			exit(1);
		}
		memset(&s, 0, sizeof(s));
		s.sin_family = AF_INET;
		if (inet_aton(devname, &s.sin_addr) == 0) {
			fprintf(stderr, "ERROR: IP address not in W.X.Y.Z format\n");
			exit(1);
		}
		s.sin_port = htons(atoi(port));
		if (connect(rfd, (struct sockaddr *) &s, sizeof(s)) < 0) {
			fprintf(stderr, "ERROR: failed to bind() socket, "
				"errno=%d\n", errno);
			exit(1);
		}
		net_connection = 1;
	} else {
		/* If devname does not exist as is, prepend '/dev/' */
		if (devname[0] != '/' && stat(devname, &statbuf) == -1) {
			len = strlen(devname) + strlen("/dev/") + 1;
			path = calloc(len, sizeof(*path));
			strncpy(path, "/dev/", len);
			strncat(path, devname, len);
		} else {
			path = strdup(devname);
		}
		if (path == NULL) {
			fprintf(stderr, "ERROR: failed to alloc() path, "
				"errno=%d\n", errno);
				exit(1);
		}
		if ((rfd = open(path, (O_RDWR | O_NDELAY))) < 0) {
			fprintf(stderr, "ERROR: failed to open() %s, "
				"errno=%d\n", path, errno);
		}
		if (path != NULL) {
			free(path);
		}
		if (rfd < 0) {
			exit(1);
		}
	}

	if (capfile != NULL) {
		if ((cfd = open(capfile, (O_WRONLY | O_TRUNC | O_CREAT), 0660)) < 0) {
			fprintf(stderr, "ERROR: failed to open(%s), errno=%d\n",
				capfile, errno);
			exit(0);
		}
	}

	if (tcpport) {
		opensoc();
	} else {
		savelocaltermios();
		setlocaltermios();
		printf("Connected.\n");
	}

	if (!net_connection) {
		if (!saveremotetermios()) {
			restorelocaltermios();
			exit(1);
		}
		if (!setremotetermios()) {
			restorelocaltermios();
			exit(1);
		}
	}

	/*
	 *	Set the signal handler to restore the old termios .
	 */
	sact.sa_handler = sighandler;
	sigaction(SIGHUP, &sact, NULL);
	sigaction(SIGINT, &sact, NULL);
	sigaction(SIGQUIT, &sact, NULL);
	sigaction(SIGPIPE, &sact, NULL);
	sigaction(SIGTERM, &sact, NULL);

	loopit();

	if (tcpport) {
		close(ifd);
		close(ofd);
	} else {
		printf("Disconnected.\n");
		if (!net_connection)
		    restoreremotetermios();
		restorelocaltermios();
	}
	if (cfd > 0)
		close(cfd);
	close(rfd);
	exit(0);
}

/*****************************************************************************/
