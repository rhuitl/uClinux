/*	From FreeBSD: */
/*
 *      tcpblast - test and estimate TCP thruput
 *
 *      Daniel Karrenberg   <dfk@nic.eu.net>
 */

/*
 *	Changes: Rafal Maszkowski <rzm@icm.edu.pl>
 *
 *	ftp://6bone-gw.6bone.pl/pub/blast/README
 */

char *vdate=
#include "version.h"
, verstr[30]="FreeBSD + rzm ";

#include <sys/types.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>	/* for Solaris */
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#if defined(__sunos__) || defined(__osf1__)
#define strerror(x)     atoi(x)
char * gettext(x) char *x; { return x; }
#endif

#define DEFBLKSIZE (1024)
#define MAXBLKSIZE (32*1024)

struct	sockaddr_in sock_in;
struct	servent *sp;
struct	hostent *host;

unsigned long starts, startms, stops, stopms, expms;
struct timeval ti; 
struct timezone tiz;

char 	greet[MAXBLKSIZE], *ind;
int 	nblocks, f;
int tcp=0, udp=0, randomb=0, blksize=DEFBLKSIZE, setbufsize=-1, dots=1, continuous=0, experimental=0;
char port[30]="9";

/* Long options.  */
static const struct option long_options[] =
{
  { "help", no_argument, NULL, 'h' },
  { "version", no_argument, NULL, 'V' },
  { NULL, 0, NULL, 0 }
};

void usage(name)
char	*name;
{	
	fprintf(stderr, "\n");
	fprintf(stderr, "usage: %s [options] destination nblocks\n\n", name);
	fprintf(stderr, "tcpblast/udpblast is a simple tool for probing network and estimating its\n");
	fprintf(stderr, "throughput. It sends nblocks of %d B blocks of data to specified\n", blksize);
	fprintf(stderr, "destination host\n\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "-b nnn         socket buf size (default: %d == %s)\n", setbufsize, setbufsize==-1 ? "don't change" : "change");
	fprintf(stderr, "-c             display speed continuously\n");
	fprintf(stderr, "-d nnn         print dot every nnn blocks, 0 disables (default %d)\n", dots);
	fprintf(stderr, "-e             add experimental way of calculating throuput\n");
/*	fprintf(stderr, "-f FILE        send FILE instead of generated data\n"); */
	fprintf(stderr, "-h, --help     this help\n");
	fprintf(stderr, "-p xyz         use port #/name xyz instead of default %s\n", port);
	fprintf(stderr, "-r             send random data\n");
	fprintf(stderr, "-s nnn         block size (default %d bytes)\n", blksize);
	fprintf(stderr, "-t             use TCP (%s)\n", ind[0]=='t' ? "default" : "default if named tcpblast" );
	fprintf(stderr, "-u             use UDP (%s)\n", ind[0]=='u' ? "default" : "default if named udpblast" );
	fprintf(stderr, "-V, --version  version\n");
	fprintf(stderr, "destination    host name or address\n");
	fprintf(stderr, "nblocks        number of blocks (1..9999)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "%s version: %s\n", name, verstr);
	exit(1);
}

void usage_small(name)
char	*name;
{	
	fprintf(stderr, "type %s --help for help\n", name);
}

/* randomize the buffer */
void
randbuff(blksize) 
int blksize;
{
	int i;
	for (i=0; i<blksize; i++) {
		greet[i]=rand() % 256;
	}
}

long
gettdiff()
{
	if (gettimeofday(&ti, &tiz) < 0)
	{
		perror("tcp/udpblast time:");
		exit(11);
	}
	stops  = ti.tv_sec;
	stopms = ti.tv_usec / 1000L;

	return (stops-starts)*1000 + (stopms-startms);
}

void
printresult(expms, datasize, buffer)
long expms;
int datasize, buffer;
{
	printf("%5d KB in %7ld msec", datasize/1024, expms);
#ifdef __uClinux__
	/* Use integer arithmetic only. */
	printf("  =  %8lld b/s", (unsigned long long) (datasize-buffer) * 8000 / expms);
	printf("  =  %7lld B/s", (unsigned long long) (datasize-buffer) * 1000 / expms);
	printf("  =  %7lld KB/s", 
		(unsigned long long) (datasize-buffer) * 1000 / (expms * 1024) );
#else
	printf("  =  %8.1f b/s", ((double)datasize-buffer)/expms*8000);
	printf("  =  %7.1f B/s", ((double)datasize-buffer)/expms*1000);
	printf("  =  %7.2f KB/s", 
		((double)datasize-buffer) / (double) (expms*1024.0) * 1000 );
#endif
	fflush(stdout);
}

int
main(argc, argv)
     int argc;
     char **argv;
{	register int i;
	int optchar;
	struct servent *service;
	int bufsize;

	strcat(verstr, vdate);

	/* non-random data - is modem compressing it? */
	bzero(greet, MAXBLKSIZE);
	memset(greet, 'a', MAXBLKSIZE); 

	/* find first letter in the name - usage() needs it */
	ind=rindex(argv[0], '/');
	if (ind==NULL) ind=argv[0]; else ind++;

	while ((optchar = getopt_long (argc, argv, "tup:rs:b:d:Vhc", long_options, NULL)) != EOF)
	switch (optchar) {
		case '\0': break;
		case 't': if (tcp==0) tcp=1;		break;
		case 'u': if (udp==0) udp=1;		break;
		case 'r': srand(0 /* may be an option */); randomb=1;	break;
		case 's': blksize=abs(atoi(optarg));	break;
		case 'b': setbufsize=abs(atoi(optarg));	break;
		case 'c': continuous=1;			break;
		case 'd': dots=abs(atoi(optarg));	break;
		case 'e': experimental=1;		break;
		case 'p': strncpy(port, optarg, sizeof(port)-1);	break;
		case 'V': printf("%s version: %s\n", argv[0], verstr);	return 0;	break;
		case 'h': usage(argv[0]);
		default: ;
	}

/* correctness */
	if (tcp && udp) {
		printf("cannot use both TCP and UDP\n");
		usage_small(argv[0]);
		exit(2);
	}

	/* if neither -t nor -u is chosen use first character of the
	   program name */
		if ( (tcp==0) && (udp==0) && (ind[0]=='t') ) tcp=1;
		if ( (tcp==0) && (udp==0) && (ind[0]=='u') ) udp=1;

	if (!tcp && !udp) {
		printf("must use either TCP or UDP\n");
		usage_small(argv[0]);
		exit(3);
	}

	if (continuous) dots=0;

	/* after options processing we need two args left */
	if (argc - optind != 2) {
		if (argc - optind != 0) printf("give both hostname and block count\n");
		usage_small(argv[0]);
		exit(4);
	}

	nblocks = atoi(argv[optind+1]);
        if (nblocks<=0 || nblocks>=INT_MAX) {
		fprintf(stderr, "%s: 1 < nblocks <= %d \n", argv[0], INT_MAX);
		exit(5);
	}


	bzero((char *)&sock_in, sizeof (sock_in));
	sock_in.sin_family = AF_INET;
	if (tcp) f = socket(AF_INET, SOCK_STREAM, 0);
	else     f = socket(AF_INET, SOCK_DGRAM, 0);
	if (f < 0) {
		perror("tcp/udpblast: socket");
		exit(6);
	}

	{ int size=sizeof(int); /* getsockopt() should know how much space we have */
		/* get/setsockopt doesn't return any error really for SO_SNDBUF,
		   at least on Linux; it limits the buffer to [2048..65536]
		   (131070 for 2.1 (?) but you can manipulate with /proc/sys/net/core/wmem_max ) */
		if (getsockopt(f, SOL_SOCKET, SO_SNDBUF, &bufsize, &size)==-1)
			printf("tcp/udpblast getsockopt: %s", strerror(errno));
		printf("read SO_SNDBUF = %d\n", bufsize);
		if (setbufsize!=-1) {
			if (setsockopt(f, SOL_SOCKET, SO_SNDBUF, &setbufsize, sizeof(setbufsize))==-1)
				printf("tcp/udpblast getsockopt: %s", strerror(errno));
			if (getsockopt(f, SOL_SOCKET, SO_SNDBUF, &bufsize, &size)==-1) /* size value's been set b4 */
				printf("tcp/udpblast getsockopt: %s", strerror(errno));
			printf("set  SO_SNDBUF = %d\n", bufsize);
		}
	}

	if (bind(f, (struct sockaddr*)&sock_in, sizeof (sock_in)) < 0) {
		perror("tcp/udpblast: bind");
		exit(7);
	}

	host = gethostbyname(argv[optind]);
	if (host) {
		sock_in.sin_family = host->h_addrtype;
		bcopy(host->h_addr, &sock_in.sin_addr, host->h_length);
	} else {
		sock_in.sin_family = AF_INET;
		sock_in.sin_addr.s_addr = inet_addr(argv[optind]);
		if (sock_in.sin_addr.s_addr == -1) {
			fprintf(stderr, "%s: %s unknown host\n", argv[0], argv[optind]);
			exit(8);
		}
	}

/* port # or name can be used */
	service = getservbyname(port, tcp ? "tcp" : "udp");
	if (service==NULL) sock_in.sin_port = htons(abs(atoi(port)));
	else               sock_in.sin_port = service->s_port;

	if (connect(f, (struct sockaddr*)&sock_in, sizeof(sock_in)) <0)
	{
		perror("tcp/udpblast connect:");
		exit(9);
	}

	printf("Sending %s %s data using %d B blocks.\n",
		randomb ? "random":"non-random", tcp ? "TCP":"UDP", blksize);

	if (gettimeofday(&ti, &tiz) < 0)
	{
		perror("tcp/udpblast time:");
		exit(10);
	}
	starts  = ti.tv_sec;
	startms = ti.tv_usec / 1000L;


	for (i=0; i<nblocks; i++)
	{
		if (randomb) randbuff(blksize);
		if (write(f, greet, (size_t)blksize) != blksize)
			perror("tcp/udpblast send:");
		if ( (dots!=0) && ( (dots==1) || (i%dots==1) ) ) write(1, ".", 1);
		if ( continuous == 1 ) {
			expms = gettdiff();
			printf("\r");
			printresult(expms, i*blksize, experimental ? bufsize : 0);
		}
	}

	expms = gettdiff();
	if (dots!=0) printf("\n");
	if (continuous) printf("\r");
	printresult(expms, nblocks*blksize, 0);
	if (experimental && (bufsize>0) && (nblocks*blksize>bufsize)) {
		printf("\nExperimentally taking into account %d B socket buffer:\n", bufsize);
		printresult(expms, nblocks*blksize, bufsize);
	}
	printf("\n");

	return(0);
}
