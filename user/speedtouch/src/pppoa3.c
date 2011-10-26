/*
 *  ALCATEL SpeedTouch USB modem utility : PPPoA implementation (3nd edition)
 *  Copyright (C) 2001 Benoit Papillault
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
 *  Author : Edouard Gomez (ed.gomez@free.fr)
 *  Creation : 08/08/2001
 *
 *  This program is designed to work under pppd, with the option "pty". It can
 *  also be used as a daemon to create a tap device that rp-pppoe can use as a
 *  standard ethernet device (this is the ethernet bridging mode rfc 1483).
 *
 *  $Id: pppoa3.c,v 1.48 2004/05/24 19:22:05 papillau Exp $
 */

#ifndef _PPPOA3_C_
#define _PPPOA3_C_

#if defined (__FreeBSD__) || defined (__linux__)
#define BRIDGING_ENABLED
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <termios.h>		/* N_HDLC & TIOCSETD */
#include <string.h>
#include <limits.h>
#include <stdarg.h>
#include <pthread.h>
#include <semaphore.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>

#ifdef USE_SYSLOG
#include <syslog.h>
#endif

#include <sys/ipc.h>
#include <sys/sem.h>

#ifdef BRIDGING_ENABLED
#ifdef __linux__
#include <net/if.h>
/* Linus says "don't include kernel stuff !"
 * so we copy stuff from <linux/if_tun.h> :-) */
#define IFF_TAP         0x0002
#define IFF_NO_PI       0x1000
#define TUNSETIFF     _IOW('T', 202, int)
#endif /* Linux */
#endif

#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* union semun is defined by including <sys/sem.h> */
#elif defined(__linux__) || defined(__NetBSD__)
/* according to X/OPEN we have to define it ourselves */
union semun {
        int val;                    /* value for SETVAL */
        struct semid_ds *buf;       /* buffer for IPC_STAT, IPC_SET */
        unsigned short int *array;  /* array for GETALL, SETALL */
        struct seminfo *__buf;      /* buffer for IPC_INFO */
};
#endif

/* USB library */
#include "pusb.h"

/* ATM library */
#include "atm.h"

/* CRC lib */
#include "crc.h"

/* Some constants */
#include "pppoa3.h"

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

/******************************************************************************
 * Local Prototypes
 ******************************************************************************/

/* I/O Threads */
static void *read_from_usb_thread(void*);
static void *write_to_usb_thread(void*);

/* Pipe thread */
static void *read_named_pipe_thread(void*);

/* Threads management */
static int thread_start(int id);
static int thread_stop(int id);
static int thread_getindex(int id);

/* Threads cleanup functions */
static void cleanup_iothread(void *arg);
static void cleanup_pipe(void *arg);

/* I/O */
static int read_source(int fd, unsigned char *buffer, int size);
static int write_dest(int fd, unsigned char *buffer, int size);
#ifdef BRIDGING_ENABLED
static int tap_open();
#endif

/* Logging facility */
static void dump(unsigned char *buf, int len);
static void report_stop();


/* Usage message */
static void usage();
static void pipe_usage();

/* Signal handler */
static void signal_handler(int signal);
static void signal_usr2(int signal);

/* async helper function */
static unsigned short pppFCS16(unsigned short fcs, 
			       unsigned char * cp,
			       int len);

/* Option parser */
static void parse_commandline(int argc, char **argv);

/******************************************************************************
 * Global data
 ******************************************************************************/

/* Instance vars and constants */
#define PPPOA3_PID_FILE_FORMAT "/var/run/pppoa3-modem%d.pid"
static int clean_previous_instance;
#define PPPOA3_SEM(modemid) ((int)('M'<<24)|('D'<<16)|('M'<<8)|(modemid&0x000000ff))


/* Input/output device descriptors */
static int fdin;
static int fdout;

/* Vpi and VCI numbers */
static int my_vpi;
static int my_vci;

/* Usb endpoint file descriptor ( shared by the threads )*/
static pusb_endpoint_t ep_data;
static pusb_device_t fdusb;
static char *device_name;
static int modem_id;

/* Logging variables */
static FILE *log;
#ifndef USE_SYSLOG
#define LOG_NAME_FORMAT "/var/log/pppoa3-modem%d.log"
static char *log_file;
#endif
static int verbose;
static int alternate_ep = 1; /* historically wasn't set. We use the
                                value since it works on all known
                                model */

/* Named pipe filename */
#define PIPE_NAME_FORMAT "/var/run/pppoa3-modem%d.pipe"
static int use_pipe;
static int pipe_fd;

/* Thread related variables */

/* #define USE_DETACH_THREADS */

#define THREAD_WRITE_TO_USB	0
#define THREAD_READ_FROM_USB	1
#define THREAD_READ_PIPE	2

typedef struct _thread_entry
{
	int		m_id;
	int		running;
	pthread_t	t_id;
	void *(*function)(void *);
	const char *name;
}thread_entry;

thread_entry thread_array[]=
{

	{
		THREAD_WRITE_TO_USB,
		(int)0,
		(pthread_t)0,
		write_to_usb_thread,
		"Read from usb"
	},
	{
		THREAD_READ_FROM_USB,
		(int)0,
		(pthread_t)0,
		read_from_usb_thread,
		"Write to usb"
	},
	{
		THREAD_READ_PIPE,
		(int)0,
		(pthread_t)0,
		read_named_pipe_thread,
		"Control pipe"
	}

};

#define NB_THREADS (int)(sizeof(thread_array)/sizeof(thread_entry))
#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
static int sched_type;
#endif

/* Used when an error is detected */
static sem_t error_sem;

/* Used when a thread needs to report a message in the logfile */
static pthread_mutex_t report_mutex;

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

/* Reading and writing buffers */
#define HDLC_HEADER_SIZE    2
#define BRIDGING1483_HEADER 10
#define AAL5_MAX_SIZE       (64*1024)
#define BUFFER_SIZE         (HDLC_HEADER_SIZE + BRIDGING1483_HEADER + \
                             1367*ATM_CELL_TOTAL_SIZE)

#if AAL5_MAX_SIZE > BUFFER_SIZE
#error BUFFER_SIZE constant must be greater than AAL5_MAX_SIZE !
#endif

#define DATA_TIMEOUT 1000

/******************************************************************************
 * Main
 ******************************************************************************/

/*
 * Function     : main
 * Return value : returns only if error is detected (error codes are != 0)
 * Description  : Initializes application threads and waits for some error
 */

int main(int argc, char **argv)
{

	const char *user;
	int i;

	/* Variables initialization */
	verbose                 = 0;
	log                     = NULL;
	use_pipe                = 0;
	pipe_fd                 =-1;
#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
	sched_type              = 0;
#endif
	my_vpi                  =-1;
	my_vci                  =-1;
	device_name             = NULL;
	modem_id                = 1;
	clean_previous_instance = 0;
	syncHDLC                = 1;
#ifdef BRIDGING_ENABLED
	bridging                = 0;
#endif
#ifndef USE_SYSLOG
	log_file                = NULL;
#endif

	/*
	 * Security stuff
	 * 1 - be sure to be root
	 * 2 - umask to prevent critical data being read from log file
	 */
	if(geteuid() != 0) {
		fprintf(stderr, "WARNING: pppoa3 must be run with root privileges\n");
		usage();
		return(-1);
	}

	/* Rights set to 0600 */
	umask(0177);

	/* Thread Mutex initilization */
	pthread_mutex_init(&report_mutex,NULL);

	/* Semaphore initialization*/
        sem_init(&error_sem, 0, 0);

	/* Parses the command line */
	parse_commandline(argc, argv);

	/* Open pty file descriptors */
#ifdef BRIDGING_ENABLED
	if(!bridging) {
#endif
		fdin  = STDIN_FILENO;
		fdout = STDOUT_FILENO;
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

	/* Gets user login */
	user = getlogin();

	if(user == NULL) {

		struct passwd *pw;

		pw = getpwuid(getuid());

		if( pw != NULL && pw->pw_name != NULL)
			user = pw->pw_name;
		else
			user = "Unknown";
	}
	
	/* Report it */
	report(0, REPORT_INFO, "pppoa3 version %s started by %s (uid %d)\n", VERSION, user, getuid());

	/* Report all parameters settings */
	report(2, REPORT_INFO, "Vpi set to %d\n", my_vpi);
	report(2, REPORT_INFO, "Vci set to %d\n", my_vci);
	report(2, REPORT_INFO, "Verbosity level set to %d\n", verbose);
#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
	report(2, REPORT_INFO, "Schedule policy set to %d\n", sched_type);
#endif
	report(2, REPORT_INFO, "Modem ID set to %d\n", modem_id);
	report(2, REPORT_INFO, "Using %s HDLC mode\n", (syncHDLC)?"Sync":"ASync");
#ifdef BRIDGING_ENABLED
	report(2, REPORT_INFO, "Using %s mode\n", (bridging)?"Bridged PPPoE":"PPPoA");
#endif
	report(2, REPORT_INFO, "Control pipe %sabled\n", (use_pipe)?"en":"dis");
	report(2, REPORT_INFO, "Previous instance cleaning %sabled\n", (clean_previous_instance)?"en":"dis");
	if(device_name)
		report(2, REPORT_INFO, "Device name set to %s\n", device_name);

#ifndef USE_SYSLOG
	report(2, REPORT_INFO, "Log filename set to %s\n", log_file);
#endif

  /*
    BP: sem_exclusive if used for two purposes:

    - it ensures that one and only one pppoa2/pppoa3 is running at the
      same time for the same modem (that's why the semaphore ID is
      derived from the modem ID).

    - if a process already exist, it can be killed (with the -c option)
  */

	/* Presents main thread */
	report(0, REPORT_INFO|REPORT_DATE, "Control thread ready\n");

	/* Gives information about the tty fds */
	report(2, REPORT_DEBUG|REPORT_DATE, "Pty descriptors : fdin=%d, fdout=%d\n",
	       fdin, fdout);

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#define SOCKBUF (64*1024)
	{
		int sbuf, ss = sizeof(sbuf);

		if(getsockopt(fdin, SOL_SOCKET, SO_SNDBUF, &sbuf, &ss) == 0) {

			report(2, REPORT_DEBUG|REPORT_DATE, "Increasing SNDBUF from %d to %d\n", sbuf, SOCKBUF);

			sbuf = SOCKBUF;

			if(setsockopt(fdin, SOL_SOCKET, SO_SNDBUF, &sbuf, ss) < 0)
				report(0, REPORT_ERROR|REPORT_DATE, "setsockopt failed\n");

		}

		if(getsockopt(fdin, SOL_SOCKET, SO_RCVBUF, &sbuf, &ss) == 0) {

			report(2, REPORT_DEBUG|REPORT_DATE, "Increasing RCVBUF from %d to %d\n", sbuf, SOCKBUF);

			sbuf = SOCKBUF;

			if(setsockopt(fdin, SOL_SOCKET, SO_RCVBUF, &sbuf, ss) < 0)
				report(0, REPORT_ERROR|REPORT_DATE, "setsockopt failed\n");

		}

	}
#endif

	/*
	 * Install HDLC line discipline on stdin if it is a tty and
	 * the OS has such a thing.
	 */

	if(isatty(fdin) && syncHDLC) {
#ifdef N_HDLC
		int disc = N_HDLC;

		if(ioctl(fdin, TIOCSETD, &disc) < 0) {
			report(0, REPORT_ERROR|REPORT_DATE, "Error loading N_HDLC\n");
			return(-1);
		}
		report(2, REPORT_DEBUG|REPORT_DATE, "N_HDLC line set up\n");
#elif defined TTYDISC
		int disc = TTYDISC;

		if(ioctl(fdin, TIOCSETD, &disc) < 0) {
			report(0, REPORT_ERROR|REPORT_DATE, "Error setting termios tty line discipline\n");
			return(-1);
		}
		report(2, REPORT_DEBUG|REPORT_DATE, "TTYDISC line set up\n");
#endif
	}

	/* Opens the modem usb device */
	if (device_name == NULL) {

		/*
		 *  No device name has been given
		 *  We search for the first USB device matching ST_VENDOR & ST_PRODUCT.
		 *  usbdevfs must be mount on /proc/bus/usb (or you may change the path
		 *  here, according to your config
		 */

		fdusb = pusb_search_open(ST_VENDOR, ST_PRODUCT);

		if(fdusb == NULL) {
			report(0, REPORT_ERROR|REPORT_DATE, "Modem not found.\n");
			return(-1);
		}


	}
	else {

		/* A device name has been given */
		fdusb = pusb_open(device_name);

		if(fdusb == NULL) {
			report(0, REPORT_ERROR|REPORT_DATE, "The modem is not at %s\n", device_name);
			return(-1);
		}

	}

	/* Debug message */
	report(1, REPORT_INFO|REPORT_DATE, "Modem found!\n");

	/* We claim interface 1, where endpoints 0x07 & 0x87 are */
	if(pusb_claim_interface(fdusb, 1) < 0) {
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

	/* Opens the end point */
	ep_data = pusb_endpoint_open(fdusb, EP_DATA_OUT, O_RDWR);

	if(ep_data == NULL) {
		report(0, REPORT_ERROR|REPORT_DATE, "pusb_endpoint_open failed\n");
		return(-1);
	}

	/* Increase priority of the pppoa process*/
	if(setpriority(PRIO_PROCESS, getpid(), -20) < 0)
		report(1, REPORT_INFO|REPORT_DATE,"setpriority failed\n");


	/* Threads Creation */
	if(thread_start(THREAD_WRITE_TO_USB) < 0) {
		report(0, REPORT_ERROR|REPORT_DATE, "Thread creation failed (%s)\n",
			thread_array[thread_getindex(THREAD_WRITE_TO_USB)].name);
		exit(1);
	}

	if(thread_start(THREAD_READ_FROM_USB) < 0) {
		report(	0, REPORT_ERROR|REPORT_DATE, "Thread creation failed (%s)\n",
			thread_array[thread_getindex(THREAD_READ_FROM_USB)].name);
		exit(1);
	}

	/* Create a thread to read named pipe data */
	if(use_pipe) {
		if(thread_start(THREAD_READ_PIPE) < 0) {
			report(0, REPORT_ERROR|REPORT_DATE, "Thread creation failed (%s)\n",
				thread_array[thread_getindex(THREAD_READ_PIPE)].name);
			exit(2);
		}
	}

	/*
	 * In *BSD, ppp  kill us with a hangup signal.
	 * In Linux,pppd kill us with a term   signal.
	 */
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	/* ppp is supposed to send SIGHUP to its pty slave so trap SIGHUP */
	signal(SIGHUP , signal_handler);
#elif defined(__linux__)
	/* on linux it's supposed to be SIGTERM */
	signal(SIGTERM, signal_handler);
	/* The problem is that pppd doesn't always do so, trap
	 * SIGPIPE and SIGHUP as well */
	signal(SIGHUP , signal_handler);
	signal(SIGPIPE , signal_handler);
#endif

	/* SIGUSR2 handler */
	signal(SIGUSR2, signal_usr2);

	/* 
	 * Waiting for an error
	 * This main thread now consumes 0 CPU until an error is broadcasted
	 * Error is broadcasted by i/o threads or the signal handler
	 */
	sem_wait(&error_sem);

	/* Reports the fatal error */
	report(0, REPORT_ERROR|REPORT_DATE, "Woken by a sem_post event -> Exiting\n");

	/* Cancels all running threads */
	for(i=0; i<NB_THREADS; i++)
		thread_stop(thread_array[i].m_id);

	/* We release all the interface we'd claim before exiting */
	if(pusb_release_interface(fdusb, 1) < 0)
		report(0, REPORT_ERROR|REPORT_DATE,"pusb_release_interface failed\n");

	/* Closes the endpoint */
	pusb_endpoint_close(ep_data);

	/* Closes the modem fd */
	pusb_close(fdusb);

	/* Closes the log file */
	report_stop();

	/* Thread Mutex destruction */
	pthread_mutex_destroy(&report_mutex);

	/* Semaphore destruction*/
	sem_destroy(&error_sem);

	return(255);

}

/******************************************************************************
 * Functions
 ******************************************************************************/

static void cleanup_iothread(void *arg)
{

	thread_entry *entry;

	if(arg != NULL) {

		/* Retrieve the array element */
		entry = (thread_entry*)arg;

		/* Mark this thread as stopped */
		entry->running = 0;

		report(1, REPORT_INFO, "Cleaning %s data\n", entry->name);

	}

}

/*
 * Function     : write_to_usb_thread
 * Return value : none
 * Description  : thread function which reads from file descriptor
 *                (ppp(d)'s pty or tun/tap device) and sends aal5 packets
 *                to the usb bus
 */

static void *write_to_usb_thread(void* arg)
{

	sigset_t signal_set;
	unsigned char *buffer;
	unsigned char *source_buf;
	unsigned char *aal5_send_buf;

	/* Configures the thread behaviour */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	/* Blocks all signals so signals are only caught by main thread */
	sigfillset(&signal_set);
	pthread_sigmask(SIG_SETMASK, &signal_set, NULL);

	/* Allocate buffer memory */
	if((buffer = malloc(BUFFER_SIZE)) == NULL)
		goto local_end;

	/* Sets a cleanup function */
	pthread_cleanup_push(cleanup_iothread, &thread_array[thread_getindex(THREAD_WRITE_TO_USB)].m_id);

	/* ... */
	report(0, REPORT_INFO|REPORT_DATE, "host  --> pppoa3 --> modem stream ready\n");

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
			report(0 , REPORT_ERROR|REPORT_DATE, "Error pppoa3 is buggy\n");
			break;
		}

		/* Debug information */
		report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "ATM cell queue built (%d bytes long)\n", aal5_send_buf, n, n);

		/* Sends data on the usb bus */
		n = pusb_endpoint_write(ep_data, aal5_send_buf, n, DATA_TIMEOUT);

		if(n > 0)
			report(2, REPORT_DEBUG|REPORT_DATE, "ATM cell queue sent to USB\n\n");

		/* Uses this as a cancel point, that's all */
		pthread_testcancel();

	}

	free(buffer);

 local_end:
	/* Broadcast the error sem to waken main thread */
	sem_post(&error_sem);

	/* Cleanup thread data */
	pthread_cleanup_pop(1);

	pthread_exit(0);

}

/*
 * Function     : read_from_usb_thread
 * Return value : none
 * Description  : thread function which reads from usb bus and sends data
 *                to a file descriptor (ppp(d)'s pty or tun/tap device)
 */
static void *read_from_usb_thread(void* arg)
{

	sigset_t signal_set;
	int pos;
	int num_bytes_read = 0;
	unsigned char *buffer;
	unsigned char *aal5_recv_buf;
	unsigned char *destination_buf;

	/* Configures the thread behaviour */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	/* Blocks all signals so signals are only caught by main thread */
	sigfillset(&signal_set);
	pthread_sigmask(SIG_SETMASK, &signal_set, NULL);

	/* Sets a cleanup function to unlink the named pipe on whatever exit*/
	pthread_cleanup_push(cleanup_iothread, &thread_array[thread_getindex(THREAD_READ_FROM_USB)].m_id);

	/* ... */
	report(0, REPORT_INFO|REPORT_DATE, "modem --> pppoa3 --> host  stream ready\n");

	/* Allocate buffer memory */
	if((buffer = malloc(BUFFER_SIZE)) == NULL)
		goto local_end;

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
		int pti;
		int num_bytes_new;
		unsigned char lbuf[64*ATM_CELL_TOTAL_SIZE];
		unsigned char *unused_cells;

		/* Reads 64*ATM_CELL_TOTAL_SIZE bytes from usb */
		do {
			n = pusb_endpoint_read(ep_data, lbuf, sizeof(lbuf), 0);
		} while (n < 0 && (errno == EINTR || errno == ETIMEDOUT));

		if(n < 0) {
			report(0, REPORT_ERROR|REPORT_DATE|REPORT_PERROR, "Error reading usb urb\n");
			break;
		}

		/* Debug information */
		report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "ATM cells read from USB (%d bytes long)\n", lbuf, n, n);


		num_bytes_read += n;      /* save total number of bytes to be processed */
		num_bytes_new = n;
		unused_cells = lbuf;      /* point at start of lbuf */

		/* Accumulate all cell-data in the aal5_recv buffer */
		/* Depending on how many cells and what type, we have to loop one or more times until everything */
		/* has been dealt with. (for example we read: cell-cell-cell-'end'cell-cell-cell-cell            */
		/* Every call to aal5_etc stops after finding an 'end'cell and then pti = 1 ) 1 cell = 53 bytes  */
		while (unused_cells != NULL) {
			pti = aal5_frame_from_atm_cells(aal5_recv_buf, unused_cells, num_bytes_new, my_vpi, my_vci, &pos, &unused_cells);

			/* 'pos' saves the place, where we are in the aal5_recv_buf */

			/* A buffer overflow has been detected */
			if (pti < 0) {
				report(0, REPORT_ERROR|REPORT_DATE, "Buffer overflow, too many cells for the same aal5 frame\n");
				pti = 0;
			}

			/* pti = 0 (more frames to follow) or pti = 1 (end of frame-group)
			 * When pti is 1, we have to send the aal5_frame data */
			if (pti == 1) {
				int nb_cells;

				/* Debug information */
				report(2, REPORT_DEBUG|REPORT_DATE|REPORT_DUMP, "AAL5 frame joined up  (%d bytes long)\n", aal5_recv_buf, pos, pos);

				/* Prepares the aal5 data (no overwrite is done)*/
				n = aal5_frame_dec(aal5_recv_buf, aal5_recv_buf, pos);

				if (n < 0) {
					report(0, REPORT_ERROR|REPORT_DATE, "CRC error in AAL5 frame\n");
				} else {
					report(2, REPORT_DEBUG|REPORT_DATE, "CRC okay  %d\n", n); 

					/* Writes the result buffer */
#ifdef BRIDGING_ENABLED
					n += (bridging)?-BRIDGING1483_HEADER:HDLC_HEADER_SIZE;
#else
					n += HDLC_HEADER_SIZE;
#endif
					if (write_dest(fdout, destination_buf, n) > 0)
 						report(2, REPORT_DEBUG|REPORT_DATE, "Extracted PPP packet sent to destination device\n");

				}

 				/* Update our buffer counters */

				/* number of payload-frames processed */
				nb_cells = pos / ATM_CELL_DATA_SIZE;

				/* calculate the rest if there is any */
 				num_bytes_read -= nb_cells*ATM_CELL_TOTAL_SIZE;
 				num_bytes_new = num_bytes_read;


				/* Reset the frame position */
 				pos = 0;
			}

		}

		/* Uses this as a cancel point, that's all */
		pthread_testcancel();

	}

	free(buffer);

 local_end:
	/* Broadcasts the error cond to wake main thread */
	sem_post(&error_sem);

	/* Cleanup thread data */
	pthread_cleanup_pop(1);

	pthread_exit(0);

}

/*
 * Function     : read_named_pipe_thread
 * Return value : none
 * Description  : thread function which reads from a named to pipe
 *                and allows users to interact with pppoa3
 */
static void cleanup_pipe(void *arg) {

	char named_pipe[128];

	/* Close the file descriptor if needed */
	if(*((int*)arg) != -1)
		close(*((int*)arg));

	/* Unlink the named pipe from the fs */
	snprintf(named_pipe, 127, PIPE_NAME_FORMAT, modem_id);
	unlink(named_pipe);

	/* Mark this thread as stopped */
	thread_array[thread_getindex(THREAD_READ_PIPE)].running = 0;

	report(1, REPORT_INFO, "Cleaning pipe data\n");

}
		
static void *read_named_pipe_thread(void *arg)
{

	fd_set set;
	sigset_t signal_set;
	char named_pipe[128];

	/* Configures the thread behaviour */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	/* Blocks all signals so signals are only caught by main thread */
	sigfillset(&signal_set);
	pthread_sigmask(SIG_SETMASK, &signal_set, NULL);

	/* Sets a cleanup function to unlink the named pipe on whatever exit*/
	pthread_cleanup_push(cleanup_pipe, &pipe_fd);

	/* Create a fifo file */
	snprintf(named_pipe, 127, PIPE_NAME_FORMAT, modem_id);
	if(mkfifo(named_pipe, 0600) != 0) {

		report(0, REPORT_ERROR|REPORT_DATE, "Named pipe creation failed -> turning off this option\n");

		/* Quit this thread */
		pthread_exit(0);
		
	}
	else {

		report(1, REPORT_INFO|REPORT_DATE, "Named pipe successfuly created\n");

		/* Opens the fifo file to allow extern access */
		if((pipe_fd = open(named_pipe, O_RDWR)) < 0) {

			report(0, REPORT_ERROR|REPORT_DATE, "Error opening the named pipe ->  turning off this option\n");

			/* Quit this thread */
			pthread_exit(0);

		}

	}

	/* ... */
	report(0, REPORT_INFO|REPORT_DATE, "Named pipe thread ready\n");

	FD_ZERO(&set);
	FD_SET(pipe_fd,&set);

	while(1) {

		int length;
		unsigned char command[128];
		unsigned char *arg;

		/* Wait for some data */
		select(pipe_fd + 1, NULL, &set, NULL, NULL);

		/* Read the data written in the pipe */
		if((length = read(pipe_fd, command, 128)) < 0)
			report(0, REPORT_ERROR|REPORT_DATE, "Error reading named pipe");

		/* Check size */
		if(length == 0 || length > 128) continue;

		for(arg=command; length>0; length--,arg++) {

			if(*arg == '=')
				break;

		}

		*arg = '\0';
		arg++;

		report(1, REPORT_INFO, "Command = %s\nArg = %s\n", command, arg);

		if(strncmp(command, "verbose", 7) == 0) {

			int level;

			level = atoi(arg);

			if(level < 0) level = - level;
			if(level > 3) level = 3;

			verbose = level;

			report(1, REPORT_INFO, "Setting verbose level to %d\n", level);

		}
#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
		else if(strncmp(command, "iopolicy", 8) == 0) {

			int pol;
			int desired_pol;
			const char *sched_string;
			struct sched_param param;

			desired_pol = atoi(arg);

			switch(desired_pol) {
			case 1: desired_pol = SCHED_RR;
				sched_string = "SCHED_RR";
				break;
			case 2: desired_pol = SCHED_FIFO;
				sched_string = "SCHED_FIFO";
				break;
			default: desired_pol = SCHED_OTHER;
				sched_string = "SCHED_OTHER";
				break;
			}

			pthread_getschedparam(	thread_array[thread_getindex(THREAD_READ_FROM_USB)].t_id,
						&pol,
						&param);
			pthread_setschedparam(	thread_array[thread_getindex(THREAD_READ_FROM_USB)].t_id,
						desired_pol,
						&param);

			pthread_getschedparam(	thread_array[thread_getindex(THREAD_WRITE_TO_USB)].t_id,
						&pol,
						&param);
			pthread_setschedparam(	thread_array[thread_getindex(THREAD_WRITE_TO_USB)].t_id,
						desired_pol,
						&param);

			report(1, REPORT_INFO, "IO threads schedule policy set to %s\n", sched_string);

		}
#endif
		else if(strncmp(command, "kill", 4) == 0) {

			if(strncmp(arg, "pipe", 4) == 0) {
				report(1, REPORT_INFO, "Killing pipe thread\n");
				break;
			}

			if(strncmp(arg, "pppoa", 5) == 0) {
				report(1, REPORT_INFO, "Killing pppoa process\n");
				sem_post(&error_sem);
				break;
			}

			report(0, REPORT_ERROR, "Unknown kill argument %s\n", arg);

		}
		else {

			report(0, REPORT_ERROR, "Unknown pipe command : %s", command);

		}
			
		/* Cancellation point */
		pthread_testcancel();

	}

	pthread_cleanup_pop(1);

	/* Quit this thread */
	pthread_exit(0);

}

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
					usleep(500);
					report(2, REPORT_DEBUG|REPORT_DATE, "500 ms delay before retry in write_dest\n");
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

/*
 * Function     : signal_handler
 * Return value : none
 * Description  : Cleans up all threads except the main one which is waiting
 *                for the error cond
 */
static void signal_handler(int signal)
{

	/* Report signal */
	report(0, REPORT_INFO|REPORT_DATE, "Received signal %d (thread %d) \n", signal, pthread_self());

	/* Broadcast the error sem */
	sem_post(&error_sem);

}

/*
 * Function     : signal_usr2
 * Return value : none
 * Description  : starts the pipe thread when sigusr2 is caught
 */
static void signal_usr2(int signal)
{

	/* Report signal */
	report(0, REPORT_INFO|REPORT_DATE, "Received signal %d (thread %d)\nEnabling Pipe thread\n", signal, pthread_self());

	/* Starts the pipe thread */
	thread_start(THREAD_READ_PIPE);

}

/*
 * Function     : thread_start
 * Return value : EAGAIN if failed, 0 if success
 * Description  : Starts the thread identified by its id
 *
 */
static int thread_start(int id)
{

	int i;
	int ret;
#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
	int policy;
#endif
	pthread_attr_t attr;

	ret = -1;

	if((i = thread_getindex(id)) < 0)
		return(-1);


	if(thread_array[i].running == 1) return(0);

	/* Threads attr(ibutes) initialization */
	pthread_attr_init(&attr);

	/* Sets detached state for all threads */
#ifdef USE_DETACH_THREADS
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
#endif

#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
	/* Sets their schedule policy */
	if(	id == THREAD_READ_FROM_USB ||
		id == THREAD_WRITE_TO_USB) {

		switch(sched_type) {
		case 1: policy = SCHED_RR;
			break;
		case 2: policy = SCHED_FIFO;
			break;
		default:policy = SCHED_OTHER;
			break;
		}
	}
	else {
		policy = SCHED_OTHER;
	}

	pthread_attr_setschedpolicy(&attr, policy);
#endif

	ret = pthread_create(	&thread_array[i].t_id,
				&attr,
				thread_array[i].function,
				NULL);

	if(ret != EAGAIN)
		thread_array[i].running = 1;

	/* Thread attributes destruction */
	pthread_attr_destroy(&attr);

	return(ret);

}

/*
 * Function     : thread_stop
 * Return value : -1 error, 0 success
 * Description  : ???
 */
static int thread_stop(int id)
{

	int i;

	if((i = thread_getindex(id)) < 0)
		return(-1);

	if(thread_array[i].running == 1) {
		pthread_cancel(thread_array[i].t_id);
		report(0, REPORT_INFO, "%s Canceled",thread_array[i].name);
#ifndef USE_DETACH_THREADS
		pthread_join(thread_array[i].t_id, NULL);
#endif
	}

	thread_array[i].running = 0;
	thread_array[i].t_id = 0;

	return(0);

}

/*
 * Function     : thread_getindex
 * Return value : -1 if thread id has not been found, thread index otherwise
 * Description  : ???
 */
static int thread_getindex(int id)
{

	int i;

	for(i=0; i<NB_THREADS; i++) {
		if(thread_array[i].m_id == id)
			return(i);
	}

	return(-1);

}

/*
 * Function     : report
 * Return value : none
 * Description  : Logs a message if verbose level is higher than
 *                the minlevel required
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
		pthread_mutex_lock(&report_mutex);

		/* if log is null, try to open the log file */
		if(log == NULL) {

#ifndef USE_SYSLOG
			char tmp[128];

			/* open the file */
			if(log_file == NULL) {
				snprintf(tmp, 127, LOG_NAME_FORMAT, modem_id);
				log_file = tmp;
			}

			if((log = fopen(log_file, "a+b")) == NULL) {

				/* UnLock the report mutex */
				pthread_mutex_unlock(&report_mutex);

				return;

			}

			/* set raw mode */
			setbuf(log, NULL);


			fprintf(log, "New log started for PPPoA3 version %s\n", VERSION);
			fprintf(log, "---------------------------------------------\n\n");
#else
			openlog("pppoa3", LOG_PID, LOG_DAEMON);
			log = (FILE*)0xcafecafe;
#endif

		}

		va_start(ap, format);

#ifndef USE_SYSLOG
		/* prints date */
		if(flags & REPORT_DATE) {
			time_t tps;
			time(&tps);
			fprintf(log, "[%.24s] ", ctime(&tps));
		}


		if(flags&REPORT_ERROR)
			fprintf(log, "Error ");
		else if (flags&REPORT_INFO)
			fprintf(log, "Info  ");
		else if (flags&REPORT_DEBUG)
			fprintf(log, "Debug ");

		if(flags)
			fprintf(log, ">%ld< ", pthread_self()); 

#endif

		/* Store the buffer we need to hexdump and its size */
		if(flags&REPORT_DUMP) {
			buffer = va_arg(ap, char*);
			length = va_arg(ap, int);
		}

#ifndef USE_SYSLOG
		vfprintf(log, format, ap);
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
			fprintf(log, "Reason : %s\n", strerror(errno));
#endif

		if(flags & REPORT_DUMP && verbose > 2)
			dump(buffer, length);

		va_end(ap);

		/* UnLock the report mutex */
		pthread_mutex_unlock(&report_mutex);

	}

	return;

}

static void report_stop()
{

#ifndef USE_SYSLOG
	report(0, REPORT_INFO|REPORT_DATE, "Closing PPPoA3 log file\n\n");

	if(log != NULL)
		fclose(log);
#else
	report(0, REPORT_INFO, "Exiting");
	closelog();
#endif

}

/*
 * Function     : parse_commandline
 * Return value : none
 * Description  : Parse the command line and initialize application parameters
 */

static void parse_commandline(int argc, char **argv)
{

	int i;
	int app_exit = 0;
	int app_pipe_usage = 0;
	int app_usage = 0;

	/* Command line scanning */
	for(i = 1; i < argc; i++)
	{

		if((strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v")) == 0 && i + 1 < argc) {
			verbose = atoi(argv[++i]);
			if(verbose<0) verbose = 0;
			else if(verbose>3) verbose = 3;
		} else if(strcmp(argv[i], "--pipe") == 0 || strcmp(argv[i], "-p") == 0) {
			use_pipe = 1;
#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
		} else if((strcmp(argv[i], "--schedule") == 0 || strcmp(argv[i], "-s") == 0) && i + 1 < argc) {
			sched_type = atoi(argv[++i]);
#endif
		} else if((strcmp(argv[i], "--vpi") == 0 || strcmp(argv[i], "-vpi") == 0) && i + 1 < argc) {
			my_vpi = atoi(argv[++i]);
		} else if((strcmp(argv[i], "--vci") == 0 || strcmp(argv[i], "-vci") == 0) && i + 1 < argc) {
			my_vci = atoi(argv[++i]);
		} else if((strcmp(argv[i], "--device") == 0 || strcmp(argv[i], "-d") == 0) && i + 1 < argc) {
			device_name = argv[++i];
		} else if((strcmp(argv[i], "--alt-ep") == 0 || strcmp(argv[i], "-e") == 0) && i + 1 < argc) {
			alternate_ep = atoi(argv[++i]);
		} else if((strcmp(argv[i], "--clean") == 0 || strcmp(argv[i], "-c") == 0)) {
			clean_previous_instance = 1;
		} else if((strcmp(argv[i], "--modem") == 0 || strcmp(argv[i], "-m") == 0) && i + 1 < argc) {
			modem_id = atoi(argv[++i]);
			modem_id = (modem_id < 0)?-modem_id:modem_id;
		} else if(strcmp(argv[i], "--pipehelp") == 0 || strcmp(argv[i], "-ph") == 0) {
			app_pipe_usage = 1;
			app_exit = 1;
		} else if(strcmp(argv[i], "--async") == 0 || strcmp(argv[i], "-a") == 0) {
			syncHDLC = 0;
#ifdef BRIDGING_ENABLED
		} else if(strcmp(argv[i], "--bridging") == 0 || strcmp(argv[i], "-b") == 0) {
			bridging = 1;
#endif
		} else if(strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			app_usage = 1;
			app_exit = 1;
#ifndef USE_SYSLOG
		} else if((strcmp(argv[i], "--filename") == 0 || strcmp(argv[i], "-f") == 0) && i + 1 < argc) {
			log_file  = argv[++i];
#endif
		} else {
			fprintf(stderr, "Unknown option '%s' -> Ignored\n", argv[i]);
		}
	}

	/* Print all usage messages */
	if(app_usage || app_pipe_usage) {

		fprintf(stderr, "pppoa3 version %s\n", VERSION);

		if(app_usage)
			usage();
		if(app_pipe_usage)
			pipe_usage();

	}

	/* Exits app if needed */
	if(app_exit)
		exit(0);

	/* vpi & vci aren't set */
	if(my_vpi == -1 || my_vci == -1) {
		report(0, REPORT_ERROR, "VPI and/or VCI value(s) missing\n");
		fprintf(stderr, "VPI and/or VCI value(s) missing (pppoa3 --help for more details)\n");
		exit(-1);
	}

#ifdef BRIDGING_ENABLED
	/*
	 * If using RFC 1483 Bridging, use syncHDLC part of the code, but of
	 * course this is not HDLC anymore.
	 */
	if(bridging)
		syncHDLC = 1;
#endif

}

/*
 * Function     : usage
 * Return value : none
 * Description  : Prints a general usage message
 *
 */

static void usage()
{

	fprintf(stderr, "Usage : pppoa3 [OPTION]... -vpi val -vci val\n");
  fprintf(stderr, "pppoa3 version %s\n\n", VERSION);
	fprintf(stderr, "Mandatory :\n\n");
	fprintf(stderr, "  -vpi | --vpi\n");
	fprintf(stderr, "             Define the vpi that your provider is using\n");
	fprintf(stderr, "  -vci | --vci\n");
	fprintf(stderr, "             Define the vci that your provider is using\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options :\n\n");
	fprintf(stderr, "  -a   | --async\n");
	fprintf(stderr, "           Force Async mode for ppp communication\n");
#ifdef BRIDGING_ENABLED
	fprintf(stderr, "  -b   | --bridging\n");
	fprintf(stderr, "           Bridging 1483 mode (PPPoE support)\n");
#endif
	fprintf(stderr, "  -c   | --clean\n");
	fprintf(stderr, "           Clean previous instance of pppoa3 according to modem id\n");
	fprintf(stderr, "  -d   | --device device_filename\n");
	fprintf(stderr, "           Force usage of the device_filename. Usefull when using\n");
	fprintf(stderr, "           more than one modem on the same machine\n");
	fprintf(stderr, "  -e   | --alt-ep alternate_endpoint\n");
	fprintf(stderr, "           Use an alternate endpoint interface (default: 1)\n");
#ifndef USE_SYSLOG
	fprintf(stderr, "  -f   | --filename filename\n");
	fprintf(stderr, "           Define the log filename to use (Default %s)\n", log_file);
#endif
	fprintf(stderr, "  -m   | --modem ID\n");
	fprintf(stderr, "           Define a modem ID so you can use more than one modem\n");
	fprintf(stderr, "           on the same machine (Default 1).\n");
	fprintf(stderr, "  -p   | --pipe\n");
	fprintf(stderr, "           Enable named pipe control thread\n");
	fprintf(stderr, "           See the -ph option for more details\n");
#ifdef _POSIX_THREAD_PRIORITY_SCHEDULING
	fprintf(stderr, "  -s   | --schedule policy\n");
	fprintf(stderr, "           Define the schedule policy used for the io threads\n");
	fprintf(stderr, "             0 - SCHED_OTHER (Non realtime scheduling / default)\n");
	fprintf(stderr, "             1 - SCHED_RR    (Realtime scheduling round-robin)\n");
	fprintf(stderr, "             2 - SCHED_FIFO  (Realtime scheduling fifo)\n");
#endif
	fprintf(stderr, "  -v   | --verbose level\n");
	fprintf(stderr, "           Define the verbosity level\n");
	fprintf(stderr, "             0 - Main messages + errors\n");
	fprintf(stderr, "             1 - Level 0 + warnings/states\n");
	fprintf(stderr, "             2 - Level 1 + More debug info\n");
	fprintf(stderr, "             3 - Level 2 + Packet dumping (can cause drivers crash)\n");
	fprintf(stderr, "  -ph  | --pipehelp\n");
	fprintf(stderr, "           An helpfull pipe command list recognized by pppoa3\n");
	fprintf(stderr, "  -h   | --help\n");
	fprintf(stderr, "           This help message\n");
}

/*
 * Function     : pipe_usage
 * Return value : none
 * Description  : Prints an usage message about pipe commands
 *
 */

static void pipe_usage()
{

	char named_pipe[128];

	snprintf(named_pipe, 127, PIPE_NAME_FORMAT, modem_id);

	fprintf(stderr, "Pipe Usage:\n\n");
	fprintf(stderr, "#echo command > %s\n\n", named_pipe);
	fprintf(stderr, "Pipe Command List\n\n");
	fprintf(stderr, "Verbosity command\n");
	fprintf(stderr, "   - Syntax      : verbose=level\n");
	fprintf(stderr, "   - Description : Defines the verbosity level\n");
	fprintf(stderr, "                   (See pppoa3 -h for available 'verbose' values)\n");
	fprintf(stderr, "IO Scheduling policy command\n");
	fprintf(stderr, "   - Syntax      : iopolicy=policy\n");
	fprintf(stderr, "   - Description : Defines the schedule policy of the 2 IO threads\n");
	fprintf(stderr, "                   (See pppoa3 -h for available 'policy' values)\n");
	fprintf(stderr, "Kill command\n");
	fprintf(stderr, "   - Syntax      : kill=entity\n");
	fprintf(stderr, "   - Description : entity represents the entity to kill, 2 possible values\n");
	fprintf(stderr, "                   pipe  -> this turn off the pipe option\n");
	fprintf(stderr, "                   pppoa -> this simulates a modem hangup event\n");
	fprintf(stderr, "\n");
	
}

/******************************************************************************
 * (Sub) Utility functions
 ******************************************************************************/

static unsigned char give_char(unsigned char c)
{

	if(c >= ' ' && c < 0x7f)
		return(c);
	else
		return('.');

}

static void dump(unsigned char *buf, int len)
{

	int i, j;

#ifndef USE_SYSLOG
	if(log == NULL)
		return;
#else
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
			fprintf(log, "%02x ", buf[j]);
#else
			sprintf(ptr, "%02x ", buf[j]);
			ptr += 3;
#endif
		}

		for(; j < i + 16; j++) {
#ifndef USE_SYSLOG
			fprintf(log, "   ");
#else
			sprintf(ptr, "   ");
			ptr += 3;
#endif
		}

		for(j = i; j < len && j < i + 16; j++) {
#ifndef USE_SYSLOG
			fprintf(log, "%c", give_char(buf[j]));
#else
			*ptr++ = give_char(buf[j]);
#endif
		}

#ifndef USE_SYSLOG
		fprintf(log, "\n");
#else
		*ptr = '\0';
		syslog(LOG_DEBUG, line);
#endif

	}
	
#ifndef USE_SYSLOG
	fprintf(log, "\n");
#endif

}

#endif
