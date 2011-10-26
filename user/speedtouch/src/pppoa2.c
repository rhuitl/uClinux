/*
*  ALCATEL SpeedTouch USB modem utility : PPPoA implementation (2nd edition)
*  Copyright (C) 2001 Benoit PAPILLAULT
*  
*  This program is free software; you can redistribute it and/or
*  modify it under the terms of the GNU General Public License
*  as published by the Free Software Foundation; either version 2
*  of the License, or (at your option) any later version.
*  
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*  
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
*  Author : Benoit PAPILLAULT <benoit.papillault@free.fr>
*  Creation : 21/03/2001
*
*  This program is designed to work under pppd, with the option "pty".
*
*  $Id: pppoa2.c,v 1.33 2004/05/24 19:22:05 papillau Exp $
*/

#ifndef _PPPOA2_C_
#define _PPPOA2_C_

#if defined (__FreeBSD__) || defined (__linux__)
#define BRIDGING_ENABLED
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <termios.h>		/* N_HDLC & TIOCSETD */
#include <string.h>
#include <limits.h>		/* for LONG_MAX */
#include <stdarg.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/resource.h>	/* setpriority() */

#ifdef USE_SYSLOG
#include <syslog.h>
#endif

#ifdef BRIDGING_ENABLED
#ifdef __linux__
/* Linus says "don't include kernel stuff !"
 * so we copy stuff from <linux/if_tun.h> :-) */
#define IFF_TAP         0x0002
#define IFF_NO_PI       0x1000
#define TUNSETIFF     _IOW('T', 202, int)
#include <linux/if.h>
#endif /* Linux */
#endif


/* Portable USB library */
#include "pusb.h"

/* ATM lib */
#include "atm.h"

/* Small semaphore library */
#include "smallsem.h"

/* For report prototype */
#include "pppoa3.h"

/*****************************************************************************
*	Defines
*****************************************************************************/

/* Key of the log's mutex */
#define	LOG_SEMKEY 0xCAFEDECA

/* USB timeout */
#define DATA_TIMEOUT 1000

/* Buffer size of buffer */
#define HDLC_HEADER_SIZE 2
#define BRIDGING1483_HEADER 10
#define AAL5_MAX_SIZE       (64*1024)
#define BUFFER_SIZE         (HDLC_HEADER_SIZE + BRIDGING1483_HEADER + \
                             1367*ATM_CELL_TOTAL_SIZE)

#if AAL5_MAX_SIZE > BUFFER_SIZE
#error BUFFER_SIZE constant must be greater than AAL5_MAX_SIZE !
#endif

/* States for scanning PPP frames */
#define STATE_WAITFOR_FRAME_ADDR 0
#define STATE_DROP_PROTO         1
#define STATE_BUILDING_PACKET    2

/* Special PPP frame characters */
#define FRAME_ESC    0x7D
#define FRAME_FLAG   0x7E
#define FRAME_ADDR   0xFF
#define FRAME_CTRL   0x03
#define FRAME_ENC    0x20

#define PPPINITFCS16    0xffff  /* Initial FCS value */

#define ASYNC_BUF_SIZE 1024

/*****************************************************************************
*	Variables
*****************************************************************************/

/* ATM Virtual Path Id and Virtual Circuit Id */
static int my_vpi = -1;
static int my_vci = -1;

/* Exclusive acces when outputing to stdout */
static int log_mutex=0;

/* Global parameters */
static int   verbose = 0;

/* processes pid_ts */
static pid_t this_process;		/*always the current   process pid*/
static pid_t parent_process;		/*always the parent    process pid*/
static pid_t handler87_process;		/*always the handler87 process pid*/

/* Sync or Async mode related stuff */
static int syncHDLC;

/* Standard PPPoA or Bridged PPPoE */
#ifdef BRIDGING_ENABLED
static int bridging;
#endif

static const unsigned short fcstab[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

/* TODO : remove this var */
static int gfdout;
static int alternate_ep = 1; /* historically wasn't set. We use the
                                value since it works on all known
                                model */

/*****************************************************************************
*	Prototypes
*****************************************************************************/

static unsigned char give_char(unsigned char c);

static int read_source(int fd, unsigned char *buffer, int n);
static int write_dest(int fd, unsigned char *buffer, int n);

static void usage();
static void sighandler(int signal);
static void dump(unsigned char *buf, int len);
#if 0
static void handle_endpoint_81(pusb_endpoint_t ep_int);
#endif
static void handle_endpoint_87(pusb_endpoint_t epdata, int fdout);
static void handle_endpoint_07(pusb_endpoint_t epdata, int fdin);

/* async helper function */
static unsigned short pppFCS16(unsigned short fcs, 
			       unsigned char * cp,
			       int len);

#ifdef BRIDGING_ENABLED
static int tap_open();
#endif


/*****************************************************************************
*       Main function
*****************************************************************************/

/*
* Function      : main
* Return Values : returns only if error is detected (error codes are != 0)
* Description   : Initializes the HDLC, log, and handle endpoints 07, 87
*                 then exit the main process.
*/
int main(int argc, char *argv[])
{
	int    fdin, fdout;
	int    i;

#ifndef USE_SYSLOG
	time_t ourtime;
	char   *logfile;
	int log;
#endif

	pusb_device_t fdusb;
	pusb_endpoint_t ep_data;
	char   *devicename = NULL;

	/* Variables initialization */
#ifndef USE_SYSLOG
	logfile  = "/var/log/pppoa2.log";
	log      = 0;
#endif
	syncHDLC = 1;
#ifdef BRIDGING_ENABLED
	bridging = 0;
#endif

	/*
	 * Security stuff
	 * 1 - be sure to be root
	 * 2 - umask to prevent critical data being read from log file
	 */
	if(geteuid() != 0) {
		fprintf(stderr, "WARNING: pppoa2 must be run with root privileges\n");
		usage();
	}

	for(i = 1; i < argc; i++)
	{
		if(strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
			verbose = atoi(argv[++i]);
			if(verbose<0) verbose = 0;
			else if(verbose>3) verbose = 3;
		} else if(strcmp(argv[i], "-vpi") == 0 && i + 1 < argc) {
			my_vpi = atoi(argv[++i]);
		} else if(strcmp(argv[i], "-vci") == 0 && i + 1 < argc) {
			my_vci = atoi(argv[++i]);
		} else if(strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			devicename = argv[++i];
		} else if(strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
			alternate_ep = atoi(argv[++i]);
#ifdef BRIDGING_ENABLED
		} else if(strcmp(argv[i], "-b") == 0) {
			bridging = 1;
#endif
#ifndef USE_SYSLOG
		} else if(strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
			logfile   = argv[++i];
#endif
		} else if(strcmp(argv[i], "--help") == 0) {
			usage();
		} else {
			usage();
		}
	}

	/*vpi & vci aren't set*/
	if(my_vpi == -1 || my_vci == -1)
		usage();

#ifdef BRIDGING_ENABLED
	/*
	 * If using RFC 1483 Bridging, use syncHDLC part of the code, but of
	 * course this is not HDLC anymore.
	 */
	if(bridging)
		syncHDLC = 1;
#endif

	/*Duplicate in and out fd*/
#ifdef BRIDGING_ENABLED
	if(!bridging) {
#endif
		fdin  = dup(STDIN_FILENO);
		fdout = dup(STDOUT_FILENO);
#ifdef BRIDGING_ENABLED
	} else {
		if((fdin  = fdout = tap_open()) == -1) {
			report(0, REPORT_ERROR, "Error opening tun/tap device. Quitting\n");
			return(-1);
		}
			
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		switch(fork()) {
		case -1: /* Error */ 
			report(0, REPORT_ERROR, "fork() failed. Quitting\n");
			return(-1);
		case 0: /* Child part */
			break;
		default: /* Parent part - just Quit */
			return(0);
		}
	}
#endif

	/*Get process pid*/
	parent_process = this_process = getpid();

#ifndef USE_SYSLOG
	/* Create the log */
	log = open(logfile, O_CREAT | O_RDWR | O_APPEND, 0600);

	/* Failed to create the log file*/
	if(log < 0)
	{
		perror(logfile);
		return(-1);
	}
#else
	openlog("pppoa2", LOG_PID, LOG_DAEMON);
#endif

	/*
	 * Check if our mutex remains from previous executions
	 * of pppoa2. If yes, destroy it. 
	 * Then create a fresh one and set its initial value to 1.
	 */
	if ((log_mutex=sem_get((key_t)LOG_SEMKEY))!=-1)
	{
		if (sem_destroy(log_mutex)==-1)
		{
#ifndef USE_SYSLOG
			perror("sem_destroy");
#else
			syslog(LOG_ERR,"sem_destroy");
#endif
			return(-1);
		}
	}
	if ((log_mutex=sem_create((key_t)LOG_SEMKEY))==-1)
	{
#ifndef USE_SYSLOG
		perror("sem_create");
#else
		syslog(LOG_ERR, "sem_create");
#endif
		return(-1);
	}
	if (sem_init(log_mutex, 1)==-1)
	{
#ifndef USE_SYSLOG
		perror("sem_init");
#else
		syslog(LOG_ERR, "sem_init");
#endif
		return(-1);
	}

	/*
	* we will redirect all standard streams to the log file
	* so we are sure to catch all messages from this program :)
	*/
#ifndef USE_SYSLOG
	if(dup2(log, STDIN_FILENO) == -1)
	{
		write(log,"Error duplicating STDIN_FILENO\n", 31);
		return(-1);
	}
	if(dup2(log, STDOUT_FILENO) == -1)
	{
		write(log,"Error duplicating STDOUT_FILENO\n", 32);
		return(-1);
	}
	if(dup2(log, STDERR_FILENO) == -1)
	{
		write(log,"Error duplicating STDERR_FILENO\n", 32);
		return(-1);
	}

	/*We don't need log fd anymore*/
	if(close(log) == -1)
	{
		fprintf(stderr, "Error closing log fd\n");
		return(-1);
	}

	/*
	* No buffering on stdout & stderr
	* So the stdout and stderr are flushed
	* each time we write to them
	*/
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

#endif

	report(0, REPORT_INFO, "Starting PPPoA2 ( merged version includes new ATM/AAL5 stack ) %s\n", VERSION);

#ifndef USE_SYSLOG
	time(&ourtime);
	report(0, REPORT_INFO, "Log started on %s\n", ctime(&ourtime));
#endif

	/* If level > 1, write the vpi,vci used */
	report(2, REPORT_INFO, "Using vpi=%d, vci=%d\n", my_vpi, my_vci);

#ifdef BRIDGING_ENABLED
	report(2, REPORT_INFO, "Using %s mode\n", (bridging)?"Bridged PPPoE":"PPPoA");
#endif
	
	/* To know what pid is the parent process */
	report(0, REPORT_INFO, "I'm the parent   process, I handle the endpoint 0x07\n", parent_process);

	/* Give information about the tty fds */
	report(1, REPORT_DEBUG, "pty descriptors : fdin=%d, fdout=%d\n", fdin, fdout);

	/* Increase priority of the pppoa process*/
	if(setpriority(PRIO_PROCESS, this_process, -20) < 0)
		report(1, REPORT_INFO|REPORT_DATE|REPORT_PERROR,"setpriority failed\n");

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define SOCKBUF (64*1024)
	{
		int sbuf, ss = sizeof(sbuf);

		if(getsockopt(fdin, SOL_SOCKET, SO_SNDBUF, &sbuf, &ss) == 0)
		{

			/*Debug message*/
			report(1, REPORT_INFO|REPORT_DATE, "Increasing SNDBUF from %d to %d\n", sbuf, SOCKBUF);

			sbuf = SOCKBUF;

			if(setsockopt(fdin, SOL_SOCKET, SO_SNDBUF, &sbuf, ss) < 0)
				report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "setsockopt failed\n");

		}

		if(getsockopt(fdin, SOL_SOCKET, SO_RCVBUF, &sbuf, &ss) == 0)
		{

			/*Debug message*/
			report(1, REPORT_INFO|REPORT_DATE, "Increasing RCVBUF from %d to %d\n", sbuf, SOCKBUF);

			sbuf = SOCKBUF;

			if(setsockopt(fdin, SOL_SOCKET, SO_RCVBUF, &sbuf, ss) < 0)
				report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "setsockopt failed\n");
		}
	}
#endif

	/*
	* Install HDLC line discipline on fdin if it is a tty and
	* the OS has such a thing.
	*/
	if(isatty(fdin))
	{
#ifdef N_HDLC
		int disc = N_HDLC;
		if(ioctl(fdin, TIOCSETD, &disc) < 0)
		{
			report(0, REPORT_ERROR|REPORT_DATE, "Error loading N_HDLC\n");
			return(-1);
		}
		report(2, REPORT_INFO|REPORT_DATE, "N_HDLC line set up\n");

#elif defined TTYDISC
		int disc = TTYDISC;
		if(ioctl(fdin, TIOCSETD, &disc) < 0)
		{
			report(0, REPORT_ERROR|REPORT_DATE, "Error setting termios tty line discipline\n");
			return(-1);
		}
		report(2, REPORT_INFO|REPORT_DATE, "TTYDISC line set up\n");

#endif
	}

	if (devicename == NULL) {
	/*
	*  We search for the first USB device matching ST_VENDOR & ST_PRODUCT.
	*  usbdevfs must be mount on /proc/bus/usb (or you may change the path
	*  here, according to your config
	*/

		fdusb = pusb_search_open(ST_VENDOR, ST_PRODUCT);

		if(fdusb == NULL)
		{
			report(0, REPORT_ERROR|REPORT_DATE, "Where is this crappy modem ?!\n");
			return(-1);
		}

	} else {

		fdusb = pusb_open(devicename);

		if(fdusb == NULL) {
			report(0, REPORT_ERROR|REPORT_DATE, "The modem is not at %s\n", devicename);
			return(-1);
		}

	}

	/*Debug message*/
	report(2, REPORT_DEBUG|REPORT_DATE, "Got the modem !\n");

	/* Initialize global variables */
	gfdout = fdout;

	/* We claim interface 1, where endpoints 0x07 & 0x87 are */
	if(pusb_claim_interface(fdusb, 1) < 0)
	{
		report(0, REPORT_ERROR|REPORT_DATE, "pusb_claim_interface 1 failed\n");
		return(-1);
	}

	if (alternate_ep != -1) {
	    /* Historically this wasn't set */
	    /* reconfigure USB (configuration & alternate settings) */
#if 0
	    if (pusb_set_configuration(fdusb,1) < 0) {
		    report(0, REPORT_ERROR, "pusb_set_configuration 1");
		    return(-1);
	    }
#endif	    
	    if (pusb_set_interface(fdusb,1,alternate_ep) < 0) {
		    report(0, REPORT_ERROR, "pusb_set_interface");
		    return(-1);
	    }
	}

	ep_data = pusb_endpoint_open(fdusb, EP_DATA_OUT, O_RDWR);
	if(ep_data == NULL)
	{
		report(0, REPORT_ERROR|REPORT_DATE, "pusb_endpoint_open failed\n");
		return(-1);
	}

	/*
	* endpoint 0x87 is used for receiving ATM cells, this function will
	* fork a new process that will read ATM cells from the usb and send them
	* to pppd
        */

	handle_endpoint_87(ep_data, fdout);

	/* At least in FreeBSD, ppp may kill us with a hangup. */
	/* In Linux, pppd kill us with a term signal ! */
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	/* ppp is supposed to send SIGHUP to its pty slave so trap SIGHUP */
	signal(SIGHUP , sighandler);
#elif defined(__linux__)
	/* on linux it's supposed to be SIGTERM */
	signal(SIGTERM, sighandler);
	/* The problem is that pppd doesn't always do so, trap
	 * SIGPIPE and SIGHUP as well */
	signal(SIGHUP , sighandler);
	signal(SIGPIPE , sighandler);
#endif

	/*
	* endpoint 0x07 is used for sending ATM cells, this function
	* is an infinite loop and will return only on errors.
        */

	handle_endpoint_07(ep_data, fdin);

	/*
	*  we kill our child pid : this is to be sure that
	*  the USB device file will be available for other programs
	*/

	if(kill(handler87_process, SIGINT) < 0)
		report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "Error killing child process %d\n", handler87_process);

	/* we release all the interface we'd claim before exiting */
	if(pusb_release_interface(fdusb, 1) < 0)
		report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR,"pusb_release_interface failed\n");

	pusb_endpoint_close(ep_data);

	pusb_close(fdusb);

	sem_destroy(log_mutex);	/* destroys the semaphore from the system */

	return(0);

}

/*****************************************************************************
*	Logging functions
*****************************************************************************/

static unsigned char give_char(unsigned char c)
{

	if(c >= ' ' && c < 0x7f)
		return(c);
	else
		return('.');

}

/*
* Function      : dump
* Return Values : none
* Description   : Dump the buffer in a log file / syslog
*/
static void dump(unsigned char *buf, int len)
{

	int i, j;

#ifdef USE_SYSLOG
	unsigned char line[128];
	unsigned char *ptr;
#endif

	if(buf == NULL || len == 0)
		return;

	for(i = 0; i < len; i += 16) {

#ifdef USE_SYSLOG
		ptr = line;
#endif

		for(j = i; j < len && j < i + 16; j++) {
#ifndef USE_SYSLOG
			printf("%02x ", buf[j]);
#else
			sprintf(ptr, "%02x ", buf[j]);
			ptr += 3;
#endif
		}

		for(; j < i + 16; j++) {
#ifndef USE_SYSLOG
			printf("   ");
#else
			sprintf(ptr, "   ");
			ptr += 3;
#endif
		}

		for(j = i; j < len && j < i + 16; j++) {
#ifndef USE_SYSLOG
			printf("%c", give_char(buf[j]));
#else
			sprintf(ptr, "%c", give_char(buf[j]));
			ptr++;
#endif
		}

#ifndef USE_SYSLOG
		printf("\n");
#else
		*ptr = '\0';
		syslog(LOG_DEBUG, line);
#endif

	}
	
#ifndef USE_SYSLOG
	printf("\n");
#endif

}

/*
* Function      : report
* Return Values : none
* Description   : Logs a message if verbose level is higher than
*                 the minlevel required
*/
void report( int minlevel, unsigned int flags, const char *format, ...)
{
	va_list ap;
	int length = 0;
	char *buffer = NULL;

	if( verbose >= minlevel ) {
#ifdef USE_SYSLOG
		char msg[256];
#endif

		/* lock the report mutex to avoid log collisions */
		sem_P(log_mutex);

		va_start(ap, format);

#ifndef USE_SYSLOG
		/* prints date */
		if(flags & REPORT_DATE) {
			time_t tps;
			time(&tps);
			printf("[%.24s] ", ctime(&tps));
		}

		if(flags&REPORT_ERROR)
			printf("Error ");
		else if (flags&REPORT_INFO)
			printf("Info  ");
		else if (flags&REPORT_DEBUG)
			printf("Debug ");

		if(flags)
			printf(">%d< ", (int)this_process); 

#endif
		/* Store the buffer we need to hexdump and its size */
		if(flags & REPORT_DUMP) {
			buffer = va_arg(ap, char*);
			length = va_arg(ap, int);
		}

#ifndef USE_SYSLOG
		vprintf(format, ap);
#else
		vsnprintf(msg, 256, format, ap);
		if(flags&REPORT_ERROR)
			syslog(LOG_ERR, msg);
		else if (flags&REPORT_INFO)
			syslog(LOG_INFO, msg);
		else if (flags&REPORT_DEBUG)
			syslog(LOG_DEBUG, msg);
#endif

#ifndef USE_SYSLOG
		/* If needed we include the strerror from libc */
		if(flags & REPORT_PERROR)
			printf("Reason : %s\n", strerror(errno));
#endif

		if(flags & REPORT_DUMP && verbose > 2)
			dump(buffer, length);

		va_end(ap);

		/* UnLock the report mutex */
		sem_V(log_mutex);
	}

	return;

}

/******************************************************************************
*	PPP i/o functions
******************************************************************************/

/*
* variable that will be used in several function
*   => so global
*/


/*
 * Function     : read_source
 * Return value : data read length
 * Description  : Reads size bytes from fd and put them in the buffer
 *                It sync hdlc 
 */

static int read_source(int fd, unsigned char *buffer, int size)
{

	/*
	 * we must handle HDLC framing, since this is what pppd
	 * sends to us. We use some code from rp-pppoe
	 */

	if(size > AAL5_MAX_SIZE) {
		report(0, REPORT_ERROR|REPORT_DATE, "Error %d bytes requested but the buffer is %d bytes long\n", size,	BUFFER_SIZE);
		return(0);
	}

	for(;;) {

		/* supress leading 2 bytes */
		if(syncHDLC) {

			int r;

			do {
				r = read(fd, buffer, size);
			} while(r < 0 && errno == EINTR);

			if(r < 0) {
				report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "Error reading from source device\n");
				return(-1);
			}

			if(!r)
				return(0);

#ifdef BRIDGING_ENABLED
			if(r < 3 && !bridging) {
#else
			if(r < 3) {
#endif
				report(0, REPORT_ERROR|REPORT_DATE, "Read from source device short on data, r=%d => ignored\n", r);
				continue;
			}

			if(r == BUFFER_SIZE) {
				report(0, REPORT_ERROR|REPORT_DATE, "Read from source device too much data, r=%d => ignored\n", r);
				continue;
			}

#ifdef BRIDGING_ENABLED
			r -= (!bridging)?HDLC_HEADER_SIZE:0;
			return(r);
#else
			return(r - HDLC_HEADER_SIZE);
#endif

		}
		else {

			static int data=0;
			static unsigned char async_buf[ASYNC_BUF_SIZE];
			static unsigned char* ptr = async_buf;
			static int PPPState=STATE_WAITFOR_FRAME_ADDR;
			static int PPPPacketSize=0;
			static int PPPXorValue=0;
		    
			if(!data) {
				ptr = async_buf;

				do {
					data = read(fd, async_buf, ASYNC_BUF_SIZE);
				} while(data < 0 && errno == EINTR);

				if(data < 0) {
					report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "Error reading from source device\n");
					return(-1);
				}

				if(!data)
					return(0);
				report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "PPP packet read from source device (%d bytes long)\n", async_buf, data, data);
			}

			if(data && PPPState == STATE_WAITFOR_FRAME_ADDR) {
				data--;
				if (*ptr++ == FRAME_ADDR) {
					PPPState = STATE_DROP_PROTO;
					PPPPacketSize = 0;
					PPPXorValue = 0;
				}
			}
		    
			if(data && PPPState == STATE_DROP_PROTO) {
				data--;
				if (*ptr++ == (FRAME_CTRL ^ FRAME_ENC)) {
					PPPState = STATE_BUILDING_PACKET;
				}
			}

			/* Start building frame */
			if(data && PPPState == STATE_BUILDING_PACKET) {
				unsigned char c = *ptr++;
				data--;
				switch(c) {
				case FRAME_ESC:
					PPPXorValue = FRAME_ENC;
					break;
				case FRAME_FLAG:
					PPPState = STATE_WAITFOR_FRAME_ADDR;
					if (PPPPacketSize < HDLC_HEADER_SIZE) {
						report(0, REPORT_ERROR|REPORT_DATE, "Read from source device short on data, PPPPacketSize=%d => ignored\n", PPPPacketSize);
						break;
					}
					return PPPPacketSize - HDLC_HEADER_SIZE;
				default:
					if(PPPPacketSize == BUFFER_SIZE-HDLC_HEADER_SIZE) {
						report(0, REPORT_ERROR|REPORT_DATE, "Read from source device too much data, PPPPacketSize=%d => ignored\n", PPPPacketSize);
						PPPState = STATE_WAITFOR_FRAME_ADDR;
						break;
					}

					buffer[2+PPPPacketSize++] = c ^ PPPXorValue;
					PPPXorValue = 0;
				}

			}

		}

	}

}

/*
 * Function     : write_dest
 * Return value : data written length
 * Description  : Writes size bytes to fd
 */

#define NOBUF_RETRIES 5
static int write_dest(int fd, unsigned char *buffer, int n)
{
	int r;
	static int errs = 0;
	int retries = 0;

	if(syncHDLC) {

	retry:

		if((r = write(fd, buffer, n)) < 0) {

			/*
			 * We sometimes run out of mbufs doing simultaneous
			 * up- and down-loads on FreeBSD.  We should find out
			 * why this is, but for now...
			 */

			if(errno == ENOBUFS) {

				errs++;

				if((errs < 10 || errs % 100 == 0))
					report(0, REPORT_ERROR|REPORT_DATE, "write_dest: %d ENOBUFS errors\n", errs);

				if(retries++ < NOBUF_RETRIES) {
					/* retry after delay */
					usleep(1000);
					goto retry;
				}
				else {
					/* throw away the packet */
					return(0);
				}

			}
			else {
				report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "Error writing to destination device\n");
			}
		}
		return(r);
	}
	else {

		static unsigned char header[4000]={FRAME_ADDR, FRAME_CTRL};
		unsigned char tail[2];
		unsigned char* ptr = &header[2];
		unsigned short fcs;
		int i;
		unsigned char c;

		/* Compute FCS */
		fcs     = pppFCS16(PPPINITFCS16, header, 2);
		fcs     = pppFCS16(fcs, buffer+2, n-2) ^ 0xffff;
		tail[0] = fcs & 0x00ff;
		tail[1] = (fcs >> 8) & 0x00ff;

		/* Build a buffer to send to PPP */
		*ptr++ = FRAME_FLAG;
		*ptr++ = FRAME_ADDR;
		*ptr++ = FRAME_ESC;
		*ptr++ = FRAME_CTRL ^ FRAME_ENC;

		for (i=2; i<n; i++) {
			c = buffer[i];
			if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
				*ptr++ = FRAME_ESC;
				*ptr++ = c ^ FRAME_ENC;
			} else {
				*ptr++ = c;
			}
		}

		for (i=0; i<2; i++) {
			c = tail[i];
			if (c == FRAME_FLAG || c == FRAME_ADDR || c == FRAME_ESC || c < 0x20) {
				*ptr++ = FRAME_ESC;
				*ptr++ = c ^ FRAME_ENC;
			} else {
				*ptr++ = c;
			}
		}
		*ptr++ = FRAME_FLAG;

		/* Ship it out */
		if ((r = write(fd, header, (ptr-header))) < 0) {
			report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "Error writing to destination device\n");
		}
		else {
			report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "PPP packet sent (%d)\n",header,(ptr-header),(ptr-header));
		}
	    
		return r;
	}

	return(-1);

}

/******************************************************************************
*	Endpoints functions
******************************************************************************/

/*
* Function      : handle_endpoint_81
* Return Values : none
* Description   : endpoint 0x81, which is on interface 0 is used for 
*                 handling 'interrupt'.
* Usage         : Currently we don't use that function as it's handle in
*                 Modem_run
*/
#if 0
static void handle_endpoint_81(pusb_endpoint_t ep_int)
{
	pid_t child_pid;

	if((child_pid = fork()) == 0)
	{
		unsigned char lbuf[64 * ATM_CELL_TOTAL_SIZE];
		int ret;

		for(;;)
		{
			ret = pusb_endpoint_read(ep_int, lbuf, sizeof(lbuf), 0);

			if(ret < 0)
			{
				report(0, REPORT_ERROR|REPORT_DATE, "Error reading interrupts\n");
				break;
			}

			report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "received interrupts, len = %d\n", lbuf, ret, ret);
		}
		_exit(0);
	}
}
#endif

/*
* Function      : handle_endpoint_87
* Return Values : none
* Description   : to handle synchronous read, we fork a new process
*                 which does an infinite loop, keeping reading on
*                 endpoint EP_DATA_IN.
*/
static void handle_endpoint_87(pusb_endpoint_t epdata, int fdout)
{
	pid_t child_pid;

	if((child_pid = fork()) == 0)
	{
		int pos;
		int num_bytes_read = 0; /* number of USB bytes not sent to upper
                	               layers (either processed or not) */
		unsigned char *buffer;
		unsigned char *aal5_recv_buf;
		unsigned char *destination_buf;

		/*
		* This is the children part of the fork()
		* child_pid doesn't mean anything, just we are a child process
		* so we get our real pid
		*/
		this_process = handler87_process = getpid();

		report(0, REPORT_INFO, "I'm the children process, I handle the endpoint 0x87\n", this_process);
		
		/* Allocate buffer memory */
		if((buffer = malloc(BUFFER_SIZE)) == NULL)
			return;
		
		/* ... */
		report(0, REPORT_INFO|REPORT_DATE, "modem --> pppoa2 --> host  stream ready\n");
	
	/* Prepares ppp buffer for HDLC */
#ifdef BRIDGING_ENABLED
		if(bridging) {
			destination_buf = buffer + BRIDGING1483_HEADER;
			aal5_recv_buf = buffer;
		} else {
#endif
			destination_buf = buffer;
			destination_buf[0] = FRAME_ADDR;
			destination_buf[1] = FRAME_CTRL;
			aal5_recv_buf = destination_buf + HDLC_HEADER_SIZE;
#ifdef BRIDGING_ENABLED
		}
#endif

		/* Prepares pos */
		pos = 0;

		/* Reads from usb and writes to ppp(d) tty */
		for(;;) {
			int n;
			int num_bytes_new; /* number of USB bytes that has not been yet
                        		    processed */
			int pti;
			unsigned char lbuf[64 * ATM_CELL_TOTAL_SIZE];
			unsigned char *unused_cells;

			/* Reads 64*53 bytes from usb */
			do {
				n = pusb_endpoint_read(epdata, lbuf, sizeof(lbuf), 0);
			} while (n < 0 && (errno == EINTR ||errno == ETIMEDOUT));

			if(n < 0) {
				report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "Error reading usb urb\n");
				break;
			}

			/* Debug information */
			report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "ATM cells read from USB (%d bytes long)\n", lbuf, n, n);

			/* initialisation for the first loop iteration */
			num_bytes_read += n;
			num_bytes_new   = n;
			unused_cells    = lbuf;

			/* Accumulates data in the aal5_recv buffer */
			/* pti will be  equal to the last cell pti */

			while (unused_cells != NULL) {
				pti = aal5_frame_from_atm_cells(aal5_recv_buf, unused_cells,
						num_bytes_new, my_vpi, my_vci,
						&pos, &unused_cells);

				/* here, if pti = 0, then unused_cells = NULL */
	
				/* A buffer overflow has been detected */
				if(pti<0) {
					report(0, REPORT_ERROR|REPORT_DATE, "Buffer overflow, too many cells for the same aal5 frame\n");
					pti = 0;
				}

				/* As the last pti is 1, we have to send the aal5_frame data */
				if (pti == 1) {

					/* Debug information */
					report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "AAL5 frame joined up  (%d bytes long)\n", aal5_recv_buf, pos, pos);

					/* Prepares the aal5 data (no overwrite is done)*/
					n = aal5_frame_dec(aal5_recv_buf, aal5_recv_buf, pos);

					if(n<0) {
						report(0, REPORT_ERROR|REPORT_DATE,"CRC error in an AAL5 frame\n");
					} else {
						report(2, REPORT_DEBUG|REPORT_DATE,"CRC okay  %d\n",n);
						/* Writes the result buffer */
#ifdef BRIDGING_ENABLED
						n += (bridging)?-BRIDGING1483_HEADER:HDLC_HEADER_SIZE;
#else
						n += HDLC_HEADER_SIZE;
#endif
						if(write_dest(fdout, destination_buf, n) > 0)
							report(2, REPORT_DEBUG|REPORT_DATE, "Extracted PPP packet sent to destination device\n\n");
					}

					num_bytes_read -= (pos / ATM_CELL_DATA_SIZE) * ATM_CELL_TOTAL_SIZE;
					num_bytes_new = num_bytes_read;

					/* Reset the frame position */
					pos = 0;
				
				}
			}
		}

		/*
		* this line is reached only if an error occurs in
		* communicating with usb or pppd
		*/
		
		free(buffer);

		/* first, we kill our father, which is useless */
		if(kill(parent_process, SIGINT) < 0)
			report(0, REPORT_DATE|REPORT_PERROR, "Error killing parent process\n");

		sem_destroy(log_mutex);	/* destroys the semaphore from the system */

		/* now we exit from this process too*/
		_exit(0);

	} else {

		/*
		* This is the parent part of the fork
		* child_pid is the pid of the forked process
		* we save it in handler87_process to be able to kill it
		* when a signal is handled by sighandler()
		*/

		handler87_process = child_pid;

	}

}

/*
* Function      : handle_endpoint_07
* Return Values : none
* Description   : to handle synchronous write, we does an infinite
*                 loop, keeping writing on endpoint EP_DATA_OUT
* Usage         : this function must be called after the
*                 handle_endpoint_87 which is a fork.
*                 handle_endpoint_07 is an infinite loop
*                 so if you enter it, you will never get
*                 out ( just when there are errors)
*/
static void handle_endpoint_07(pusb_endpoint_t epdata, int fdin)
{
	/* this part still need a redesign ... */
	unsigned char *buffer;
	unsigned char *source_buf;
	unsigned char *aal5_send_buf;
	
	/* Allocate buffer memory */
	if((buffer = malloc(BUFFER_SIZE)) == NULL)
		return;

	/* ... */
	report(0, REPORT_INFO|REPORT_DATE, "host  --> pppoa2 --> modem stream ready\n");

#ifdef BRIDGING_ENABLED
	if(bridging) {

		/*
		 * When bridging aal5 frames will never use more than 1500 bytes
		 * because max eth frames are 15000 bytes long, so there is no
		 * buffer overflow possible here even if we use 10 bytes more
		 */
		aal5_send_buf = buffer;
		source_buf = buffer + BRIDGING1483_HEADER;
		
	} else {
#endif
		source_buf = buffer;
		aal5_send_buf = buffer + HDLC_HEADER_SIZE;
#ifdef BRIDGING_ENABLED
	}
#endif
	
									
	/* Reads from ppp(d) tty and writes to usb bus */
	for(;;) {

		int n;
		/* Reads data from ppp(d) */
#ifdef BRIDGING_ENABLED
		if(bridging) {
			aal5_send_buf[0]=0xaa;
			aal5_send_buf[1]=0xaa;
			aal5_send_buf[2]=0x03;
			aal5_send_buf[3]=0x00;
			aal5_send_buf[4]=0x80;
			aal5_send_buf[5]=0xc2;
			aal5_send_buf[6]=0x00;
			aal5_send_buf[7]=0x07;
			aal5_send_buf[8]=0x00;
			aal5_send_buf[9]=0x00;
		}
#endif

		n = read_source(fdin, source_buf, AAL5_MAX_SIZE);

		if(n <= 0)
			break;

#ifdef BRIDGING_ENABLED
		n += (bridging)?BRIDGING1483_HEADER:0;
#endif

		/* Debug information */
		report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "PPP packet read from source device (%d bytes long)\n", aal5_send_buf, n, n);

		/* Creates the aal5 frame */
		n = aal5_frame_enc(aal5_send_buf, aal5_send_buf, n);

		/* Builds a queue of atm cells from the aal5 frame */
		n = aal5_frame_to_atm_cells(aal5_send_buf, aal5_send_buf, n, my_vpi, my_vci);

		if(n < 0) {
			report(0 , REPORT_ERROR|REPORT_DATE, "Error pppoa2 is buggy\n");
			break;
		}

		/* Debug information */
		report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "ATM cell queue built (%d bytes long)\n", aal5_send_buf, n, n);

		/* Sends data on the usb bus */
		n = pusb_endpoint_write(epdata, aal5_send_buf, n, DATA_TIMEOUT);

		if(n > 0)
			report(2, REPORT_DEBUG|REPORT_DATE, "ATM cell queue sent to USB\n\n");
	}

	free(buffer);

	return;
}

/*
* Function      : usage
* Return Values : None
* Description   : Prints an usage message
*/
static void usage()
{
	fprintf(stderr, "Usage: pppoa2 [OPTION]... -vpi val -vci val\n");
	fprintf(stderr, "pppoa2 version %s\n\n", VERSION);
	fprintf(stderr, "  -v       : defines the verbosity level [0-3]\n");
	fprintf(stderr, "  -vpi     : define the vpi of your provider\n");
	fprintf(stderr, "  -vci     : define the vci of your provider\n");
	fprintf(stderr, "  -d device: define the device to use\n");
	fprintf(stderr, "  -e number: use an alternate endpoint interface (default: 1)\n");
#ifdef BRIDGING_ENABLED
	fprintf(stderr, "  -b       :  Bridging 1483 mode (PPPoE support)\n");
#endif
#ifndef USE_SYSLOG
	fprintf(stderr, "  -f       : defines the log filename to use ( Default /var/log/pppoa2.log )\n");
#endif
	fprintf(stderr, "  --help   : this message\n");
	exit(-1);
}

/*
* Function      : sighandler
* Return Values : None
* Description   : Die on a hangup, and propagate it to the handler_87 process
*/
static void sighandler(int signal)
{
	/*We kill the handler87 handler process*/
	if(kill(handler87_process, signal) < 0)
		report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "Error killing handler87 process\n");

	report(0, REPORT_INFO|REPORT_DATE, "Killed by a signal %d\n", signal);

	sem_destroy(log_mutex);	/* destroys the semaphore from the system */

	/* We exit safely*/
	_exit(1);
}

/*
 * Function     : pppFCS16
 * Arguments    :
 *                fcs -- current fcs
 *                cp  -- a buffer's worth of data
 *                len -- length of buffer "cp"
 * Return value : A new FCS
 * Description  : Updates the PPP FCS
 *
 * NB : "stolen" from rp-pppoe
 */

static unsigned short pppFCS16(unsigned short fcs, 
			       unsigned char * cp, 
			       int len)
{

	while(len--)
		fcs = (fcs >> 8) ^ fcstab[(fcs ^ *cp++) & 0xff];
    
	return(fcs);

}

/*
 * Function     : tap_open
 * Arguments    :
 *                none
 * Return value : a file descriptor
 * Description  : Updates the PPP FCS
 *
 */

#ifdef BRIDGING_ENABLED
static int tap_open()
{
	int fd;

#if defined (__FreeBSD__)
  int i;
  char devname[] = "/dev/tapXX";

  for (i=0;i<100;i++)
  {
      sprintf(devname,"/dev/tap%d",i);
      fd = open(devname, O_RDWR | O_FSYNC);
      if (fd < 0) {
          continue;
      }

      printf("%s\n",devname);
      fflush(stdout);
      break;
  }
#elif defined(__linux__) /* end of __FreeBSD__ code path */
	struct ifreq ifr;
	int err;

	if( (fd = open("/dev/net/tun", O_RDWR | O_SYNC)) < 0 )
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
		close(fd);
		return err;
	}

  /* print interface name on stdout */
  printf("%s\n",ifr.ifr_name);
  fflush(stdout);

#endif /* end of __linux__ code path */

	return fd;
}
#endif

#endif /* _PPPOA2_C_ */
