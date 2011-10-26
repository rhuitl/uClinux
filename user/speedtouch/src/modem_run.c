/*
*  ALCATEL SpeedTouch USB modem microcode upload & ADSL link UP utility
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
*  Author   : Benoit PAPILLAULT <benoit.papillault@free.fr>
*  Creation : 05/03/2001
*  
*  This program uploads the microcode to the ALCATEL SpeedTouch USB modem.
*  
*  The microcode can be uploaded only once. If the upload is correct,
*  ADSL led should be both green & red.
*  
*  If you try to download the microcode twice, you will get tons of
*  timeout errors.
*
*  $Id: modem_run.c,v 1.44 2004/06/03 23:29:27 papillau Exp $
*/

#ifndef _MODEM_RUN_C_
#define _MODEM_RUN_C_

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>     /* for errno */
#include <stdarg.h>
#include <syslog.h>
#include <pwd.h>

#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "pusb.h"
#include "modem.h"
#include "pppoa3.h"
#include "firmware.h"
#include "mutex.h"

/******************************************************************************
* Defines
******************************************************************************/

/* Timeout in milliseconds */
#define CTRL_TIMEOUT 2000
#define DATA_TIMEOUT 2000

#define OFFSET_7  0 /* size 1 */
#define OFFSET_b  1 /* size 8 */
#define OFFSET_d  9 /* size 4 */
#define OFFSET_e 13 /* size 1 */
#define OFFSET_f 14 /* size 1 */
#define TOTAL    15

#define SIZE_7 1
#define SIZE_b 8
#define SIZE_d 4
#define SIZE_e 1
#define SIZE_f 1

enum {
    S_INIT = 0,
    S_LINE_KO,
    S_LINE_OK
};

#define MUTEX_ID 0xdeadbeef

/*****************************************************************************
* Global variables
******************************************************************************/

static int verbose = 0;
FILE *flog = NULL;

/*****************************************************************************
* Local Variables
*****************************************************************************/

static int dl_512_first = 1; /* Try to download 512 bytes before first op */
static int link_up = 0;      /* Used to gives link state between 2 processes */
static int timed_out = 0;    /* Used to give a timeout signal inside the wait loop */
static int sb = 0;           /* Software buffering */
static int signal_kernel = 0;/* Kernel driver notification */

/******************************************************************************
* Prototypes
******************************************************************************/

static int  upload_firmware(pusb_device_t fdusb, const stusb_firmware_t *firmware);
static int  get_reference(pusb_device_t fdusb);
static int  modem_start_synchro(pusb_device_t fdusb);
static void swbuff(pusb_device_t fdusb, int state);
static int  get_state(pusb_device_t fdusb, unsigned char *buf);
static int  poll_state(pusb_device_t fdusb, unsigned char *prev_state);
static int  print_state(unsigned char *buf);

static void usage();
static void test_sequence(pusb_device_t fdusb);
static void fork_interrupt_daemon(pusb_device_t fdusb);


static void report_stop();
static void dump(unsigned char *buf, int len);
static unsigned char give_char(unsigned char c);

static void signal_alrm(int sig);
static void signal_usr1(int sig);

/*****************************************************************************
*	Main function
*****************************************************************************/

/*
* Function      : main
* Return Values : ?
* Description   : Does all the job (that's fantastic :)
*/
int sub_main(int argc, char *argv[])
{

	pusb_device_t fdusb;
	int i;
	unsigned char state[TOTAL+1000];
	const char *firm_file = NULL;
	const char *boot_file = NULL;
	char *devicename = NULL;
	const char *user;
	int timeout = 120; /* Wait for 120s before giving up */
	int polling_interval = 10; /* Polling device state interval in seconds */
	int upload_tries = 10;
	stusb_firmware_t *firmware = NULL;
	int revision = -1;
    int semid, val, do_exit = 0, do_exit_code = 0;
	
	/*
	* Security stuff
	* 1 - be sure to be root
	* 2 - umask to prevent critical data being read from log file
	*/
	if(geteuid() != 0) {
		fprintf(stderr, "WARNING: modem_run must be run with root privileges\n");
		usage();
	}

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

	report(0, REPORT_INFO, "modem_run version %s started by %s uid %d\n", VERSION, user, getuid());

	for (i=1;i<argc;i++) {
		 if (strcmp(argv[i], "-a") == 0 && i+1<argc) {
			 boot_file = argv[++i];
		 } else if (strcmp(argv[i], "-b") == 0) {
			 sb = 1;
		 } else if (strcmp(argv[i], "-d") == 0 && i+1<argc) {
			 devicename = argv[++i];
		 } else if (strcmp(argv[i], "-f") == 0 && i+1<argc) {
			 firm_file = argv[++i];
		 } else if (strcmp(argv[i], "-i") == 0 && i+1<argc) {
			 polling_interval = atoi(argv[++i]);
		 } else if (strcmp(argv[i], "-k") == 0) {
			 signal_kernel = 1;
		 } else if (strcmp(argv[i], "-n") == 0 && i+1<argc) {
			 upload_tries = atoi(argv[++i]);
		 } else if (strcmp(argv[i], "-r") == 0 && i+1<argc) {
			 revision = atoi(argv[++i]);
		 } else if (strcmp(argv[i], "-s") == 0) {
			 dl_512_first = 0;
		 } else if (strcmp(argv[i], "-t") == 0 && i+1<argc) {
			 timeout = atoi(argv[++i]);
		 } else if (strcmp(argv[i], "-v") == 0 && i+1<argc) {
			 verbose = atoi(argv[++i]);
		 } else if (strcmp(argv[i],"--help") == 0) {
			 usage();
		 } else if (strcmp(argv[i],"-m") == 0) {
			 /* NOP: here for backward compatibility */
		 } else {
			 usage();
		 }
	}
	
	if (firm_file == NULL)
		usage();
	if (boot_file == NULL)
		boot_file = firm_file;

	/* Sanitize some values */
	if (timeout <= 0)
		timeout = 120;

	if (polling_interval >= timeout || polling_interval <= 0) {
		polling_interval = timeout;

		/* To avoid races between the polling and the SIGALRM trigger,
		 * create a small delta */
		polling_interval -= 2;

		/* we will poll 6 times by default (arbitrary choice) */
		polling_interval /= 6;

		/* Sanitize again if we've gone under logical values */
		polling_interval = (polling_interval<1)?1:polling_interval;
	}

	/* Try top upload at least one time */
	if (upload_tries < 0)
		upload_tries = 1;

	/* For unsane revision numbers, just try auto detection (==-1) */
	if (revision < -1 || revision > 4)
		revision = -1;		

    /* Check if another modem_run is running (warning: does not handle
     * several modems */

    semid = mutex_init(MUTEX_ID, S_INIT);
    if (semid < 0) {
        perror("Failed to create mutex\n");
        return -1;
    }

    if (mutex_lock(semid) < 0) {
        fprintf(stderr,"modem_run is already running\n");
        return -1;
    }

    val = mutex_getval(semid);

    switch (val)
    {
    case S_INIT:
        if (mutex_setval(semid, S_LINE_KO) < 0) {
            perror("mutex_setval");
        }
        do_exit = 0;
        break;

    case S_LINE_KO:
        do_exit = 1;
        do_exit_code = -1;
        break;

    case S_LINE_OK:
        do_exit = 1;
        do_exit_code = 0;
        break;
    }

    if (mutex_unlock(semid) <0) {
        perror("mutex_unlock");
    }

    if (do_exit) {
        exit(do_exit_code);
    }

	/* we search the modem on the USB bus */
	if (devicename == NULL) {

		fdusb = pusb_search_open(ST_VENDOR,ST_PRODUCT);

		if (fdusb == NULL) {
			report(0, REPORT_ERROR, "No SpeedTouch USB found.\n");
			return(-1);
		}

	}
	else {

		fdusb = pusb_open(devicename);

		if(fdusb == NULL) {
			report(0, REPORT_ERROR, "No SpeedTouch USB at %s\n", devicename);
			return(-1);
		}

	}
	
	report(1, REPORT_INFO, "Found SpeedTouch USB modem\n");

	/* Retrieve the revision number if autodetection is requested */
	if (revision == -1) {
		revision = pusb_get_revision(fdusb);
		if (revision == -1) {
			revision = 2;
			report(0, REPORT_INFO, "Modem revision could not be retrieved, assuming Rev 0200 modem.\n");
		} else {
			report(1, REPORT_INFO, "Modem revision: %04x\n", revision);
			switch(revision) {
			case 0x0000:
				revision = 0;
				break;
			case 0x0200:
				revision = 2;
				break;
			case 0x0400:
				revision = 4;
				break;
			default:
				revision = 2;
				report(0, REPORT_INFO, "Unexpected modem revision %04x, assuming Rev 0200 modem.\n");
				break;
			}
		}
	} else {
		report(1, REPORT_INFO, "Assuming modem revision: %d\n", revision);
	}

	/* we check that no one else is already using the modem,
	 * by claiming (ie requesting exclusive use) interface 0, 1 & 2,
	 * which are all the interfaces of the USB modem. */
	if (pusb_claim_interface(fdusb, 2) < 0) {
		report(0, REPORT_ERROR, "Another program/driver is already accessing the modem (interface 2 cannot be claimed)...\n");
		return(-1);
	}

  /*
    pusb_set_configuration() triggers hotplug. All previous interfaces
    are removed and all new interfaces are added. In our example, it
    makes 6 calls to usb.agent (tested on 2.6.5).

    Both in 2.4 and 2.6 kernels, there is an initial call to
    pusb_set_interface() to set the default interface before calling
    hotplug. So, all call to pusb_set_interface() are useless since
    there is only one interface.
  */
#if 0
	if (pusb_set_configuration(fdusb, 1) < 0) {
		report(0, REPORT_ERROR, "pusb_set_configuration 1");
		return(-1);
	}
#endif	
	/* Retrieves the microcode from file "filename" */
	if ((firmware = extract_firmware(boot_file, firm_file, (revision==4)?1:0)) == NULL) {
		/* this is a fatal error, either the file cannot be read
		* or the microcode is not inside the firm file */
		report(0, REPORT_ERROR, "Unable to locate firmware in %s\n", firm_file);
		pusb_close(fdusb);
		report_stop();
		return(-1);
	}

	if (firmware->phase1 == NULL) {
		report(0, REPORT_ERROR, "Unable to locate boot code in %s\n", boot_file);
		pusb_close(fdusb);
		report_stop();
		return(-1);
	}

	/* This case should not happen because if main part is missing, the
	 * extract firmware function would have returned NULL. Anyway, write
	 * the test so we are extra careful */
	if (firmware->phase2 == NULL) {
		report(0, REPORT_ERROR, "Unable to locate main firmware code in %s\n", firm_file);
		pusb_close(fdusb);
		report_stop();
		return(-1);
	}


	/* For some extremely rare modems, the first upload fails
	 * The workaround is simple : we try a specified number of times */
	for(i=0; i<upload_tries; i++) {
		if (upload_firmware(fdusb, firmware) < 0) {
			report(1, REPORT_ERROR, "Retrying to upload microcode (#%d)\n", i);
			continue;
		}
		break;
	}

	/* Free the firmware allocated mem */
	free_firmware(firmware);
	firmware = NULL;

	/* It failed all the times */
	if(i == upload_tries) {
		if (pusb_release_interface(fdusb, 2) < 0)
			perror("pusb_release_interface 2");
		pusb_close(fdusb);
		report_stop();
		return(-1);
	}
	
	/*
	 * Ok the microcode is loaded, wait a bit before asking him
	 * the adsl sync
	 */
	sleep(1);
	
	if (pusb_claim_interface(fdusb, 0) < 0) {
		report(0, REPORT_ERROR, "Another program/driver is already accessing the modem (interface 0 cannot be claimed)...\n");
		return(-1);
	}

	/* reconfigure USB (configuration & alternate settings) */
#if 0 /* see the previous disabled call to interface for an explaination
	 why this call is bisabled */
	if (pusb_set_configuration(fdusb, 1) < 0) {
		report(0, REPORT_ERROR, "pusb_set_configuration 1");
		return(-1);
	}
#endif
	if (pusb_claim_interface(fdusb,1) < 0) {
		if (!signal_kernel) {
			report(0, REPORT_ERROR, "Another program/driver is already accessing the modem (interface 1 cannot be claimed)...\n");
			return(-1);
		}
		report(1, REPORT_INFO, "Found kernel mode driver\n");
	} else { /* claimed interface 1 */
		int ep = 1;

		if (signal_kernel) {
			report(0, REPORT_ERROR, "Kernel mode driver not found\n"); 
			signal_kernel = 0;
		}

		/* Revision 0 modems require the use of the endpoint 2 */
		if (revision == 0)
			ep = 2;

		if (pusb_set_interface(fdusb, 1, ep) < 0) {
			report(0, REPORT_ERROR, "pusb_set_interface");
			return(-1);
		}
	}

	/* Enable software buffering - Courtesy of Thomson Multimedia */
	if(sb) swbuff(fdusb,1);

	/* 
	 * We register the signal handler that will be used to signal
	 * the up state of the link.
	 */
	signal(SIGALRM , signal_alrm);

	/*
	 * Start a subprocess (the so called daemon) to make sure the
	 * interrupt endpoint is always writable (because we read it there)
	 */
	fork_interrupt_daemon(fdusb);

	/* Cosmetic */
	get_reference(fdusb);

	/* Magic spell, don't ask us what this does */
	test_sequence(fdusb);
	
	/* should start line sync */
	modem_start_synchro(fdusb);

	/*
	 * New method : The child which reads the interrupt endpoint
	 *              notices the parent process of the up link.
	 *
	 * Parent will wait for 'timeout' seconds before giving up connection.
	 */

	/* Launch the alarm so even if the modem doesn't sync, the program will
	 * exit. This is useful when run from a startup script */
	alarm(timeout);

	/* Poll the device state */
	while(link_up <= 0 && !timed_out) {
		link_up = poll_state(fdusb, state);
		sleep(polling_interval);
	}

	/* XXX: temporary solution
	 * Revision 4 modems make the interrupt daemon blocks forever on read.
	 * So the daemon process never notifies the kernel about the line state.
	 * So we do notify the kernel module here instead, but that doesn't solve
	 * the root of the problem as the kernel module isn't told if the line
	 * goes down (then up) later (because the child process is still
	 * blocking */
	if (revision == 4 && signal_kernel) {
		pusb_ioctl(fdusb, 1, 1, NULL);
	}

	/* Reset the alarm signal - no races possible (see the USR2 signal hanlder) */
	alarm(0);

	if (timed_out) {
	        report(0, REPORT_ERROR, "ADSL synchronization timed out - the monitoring instance will report further state changes\n");
	} else {
	        /* The physical adsl link has been established */
	        report(0, REPORT_INFO, "ADSL synchronization has been obtained\n");
		/* We can print the adsl link state (speed) */
		print_state(state);

        /* change the value of our shared variable */
        mutex_setval(semid, S_LINE_OK);
	}

	/* Close all */
#if !defined(__linux__)
	/* The interface 0 used to be released on all platforms but newer
	 * linux kernels care about interfaces accross processes, so if we
	 * release it there, the child will use it w/o having claimed it */
	if (pusb_release_interface(fdusb,0) < 0)
 		report(0, REPORT_ERROR, "pusb_release_interface 0 failed");
#endif

	if (!signal_kernel && pusb_release_interface(fdusb,1) < 0)
		report(0, REPORT_ERROR, "pusb_release_interface 1 failed");

	if (pusb_release_interface(fdusb,2) < 0)
		report(0, REPORT_ERROR, "pusb_release_interface 2 failed");
	
	pusb_close(fdusb);

	report_stop();
	
	return((!timed_out)? 0 : -1);
}

/*
  main() function. We just fork() to execute the real main function
  (sub_main) and wait for either its termination or SIGUSR1 signal.
*/

int main(int argc, char * argv[])
{
    int status;
    pid_t pid;

    signal(SIGUSR1, signal_usr1);

    switch (fork())
    {
    case 0: /* child process */
        exit (sub_main(argc, argv));
        break;

    case -1: /* error */
        perror ("fork");
        exit (-1);
        break;

    default: /* parent process */

        while ( (pid=wait (&status)) > 0) {
            /* if our child died, we exit with the same exit code */
            if (WIFEXITED(status)) {
                exit (WEXITSTATUS(status));
            }
        }
        break;
    }

    return 0;
}

/*****************************************************************************
*	Subroutines
*****************************************************************************/

/*
* Function      : usage
* Return Values : None
* Description   : Prints an usage message
*/
static void usage()
{

	fprintf(stderr, "usage: modem_run [OPTION]... -f firmware\n");
	fprintf(stderr, "modem_run version %s\n", VERSION);
	fprintf(stderr, "Mandatory:\n");
	fprintf(stderr, "  -f firmware  : firmware filename to upload (mandatory)\n");
	fprintf(stderr, "                 This file is scanned to extract both boot and main part of\n");
	fprintf(stderr, "                 firmware\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -a bootcode  : bootcode filename to upload (optional)\n");
	fprintf(stderr, "                 This file is scanned to extract the boot code of the modem\n");
    fprintf(stderr, "  -b           : enable software buffering mode\n");
	fprintf(stderr, "  -d device    : defines the device to use\n");
	fprintf(stderr, "                 The -a option overides the -f option for the boot code part\n");
	fprintf(stderr, "  -i seconds   : seconds between each line state testing (default 10s)\n");
	fprintf(stderr, "  -k           : using the kernel mode driver\n");
	fprintf(stderr, "  -n number    : number of firmware loading tries before it is considered\n");
	fprintf(stderr, "                 failure\n");
	fprintf(stderr, "  -r number    : forces a specific modem revision (0 to 4, default is autodetection)\n");
	fprintf(stderr, "  -s           : skip the first 512 bytes read\n");
	fprintf(stderr, "  -t seconds   : synchronization timeout (default 120s)\n");
	fprintf(stderr, "                 After the timeout expires, the main process quits but the\n");
	fprintf(stderr, "                 monitoring daemon remains reporting the line state\n");
	fprintf(stderr, "  -v           : verbose level [0-2]\n");
	fprintf(stderr, "  --help       : this message\n");
	exit(-1);

}

/*
* Function      : upload_firmware
* Return Values : -1 in case of error
* Description   : [...]
* NB            : This functions require the modem interface 2
*/
static int upload_firmware(pusb_device_t fdusb, const stusb_firmware_t *firmware)
{
	int n;
	unsigned char buf[0x1000]; /* buf should be at least 511 bytes */
	struct timeval start, stop;
	pusb_endpoint_t ep_code;

	/* open the EP_CODE endpoint */
	if ((ep_code = pusb_endpoint_open(fdusb,EP_CODE_IN,O_RDWR)) == NULL) {
		report(0, REPORT_ERROR, "pusb_endpoint_open");
		exit(-1);
	}
	
	/* URB 7 */
	if(dl_512_first){
		memset(buf, 0, sizeof(buf));
		gettimeofday(&start,NULL);
		n = pusb_endpoint_read(ep_code, buf, 0x200,DATA_TIMEOUT);
		gettimeofday(&stop,NULL);

		if (n < 0) {
			if (errno != ETIMEDOUT) {
				report(0, REPORT_ERROR, "BLOCK0\n");
				pusb_endpoint_close(ep_code);
				return(n);
			}
		} else {
			report(1, REPORT_INFO, "BLOCK0 : %6d bytes downloaded : OK\n", n);
			report(2, REPORT_DEBUG|REPORT_DUMP,"Downloaded in %f ms\n",
			       buf,
			       n,
			       (double)(stop.tv_sec -start.tv_sec) * 1000.0 +
			       (double)(stop.tv_usec - start.tv_usec) / 1000.0);
		}
	}
	
	/* URB 8 : both leds are static green */
	gettimeofday(&start,NULL);
	n = pusb_endpoint_write(ep_code, firmware->phase1, firmware->phase1_length, DATA_TIMEOUT);
	gettimeofday(&stop,NULL);

	if (n < 0) {
		report(0, REPORT_ERROR, "BLOCK1\n");
		pusb_endpoint_close(ep_code);
		return(n);
	} else {
		report(1, REPORT_INFO, "BLOCK1 : %6d bytes   uploaded : OK\n", firmware->phase1_length);
		report(2, REPORT_DEBUG|REPORT_DUMP,"Downloaded in %f ms\n",
		       firmware->phase1,
		       firmware->phase1_length,
		       (double)(stop.tv_sec -start.tv_sec) * 1000.0 +
		       (double)(stop.tv_usec - start.tv_usec) / 1000.0);

	}
	
	/*
	* After usb_bulk_write :
	*   + USB  led : blinking green
	*   + ADSL led : off
	*/
	
	/* URB 11 */
	memset(buf, 0, sizeof(buf));
	gettimeofday(&start,NULL);
	n = pusb_endpoint_read(ep_code,buf,0x200,DATA_TIMEOUT);
	gettimeofday(&stop,NULL);

	if (n < 0) {
		report(0, REPORT_ERROR, "BLOCK2\n");
		pusb_endpoint_close(ep_code);
		return(n);
	} else {
		report(1, REPORT_INFO, "BLOCK2 : %6d bytes downloaded : OK\n", n);
		report(2, REPORT_DEBUG|REPORT_DUMP,"Downloaded in %f ms\n",
		       buf,
		       n,
		       (double)(stop.tv_sec -start.tv_sec) * 1000.0 +
		       (double)(stop.tv_usec - start.tv_usec) / 1000.0);
	}
	
	
	/* URB 12 to 139 */
	gettimeofday(&start,NULL);
	n = pusb_endpoint_write(ep_code, firmware->phase2, firmware->phase2_length, DATA_TIMEOUT);
	gettimeofday(&stop,NULL);
	
	if (n < 0) {
		report(0, REPORT_ERROR, "BLOCK3\n");
		pusb_endpoint_close(ep_code);
		return(n);
	} else {
		report(1, REPORT_INFO, "BLOCK3 : %6d bytes   uploaded : OK\n", n);
		report(2, REPORT_DEBUG, "Downloaded in %f ms\n", 
		       (double)(stop.tv_sec -start.tv_sec) * 1000.0 +
		       (double)(stop.tv_usec - start.tv_usec) / 1000.0);
	}

	/*
	* Before downloading microcode :
	*   + USB  led : blinking
	*   + ADSL led : off
	*   
	* During downloading:
	*   + USB  led : blinking green
	*   + ADSL led : off
	*   
	* After downloading microcode :
	*   + USB  led : static green
	*   + ADSL led : static red
	*/
	
	/* URB 142 */
	memset(buf, 0, sizeof(buf));
	gettimeofday(&start,NULL);
	n = pusb_endpoint_read(ep_code,buf,0x200,DATA_TIMEOUT);
	gettimeofday(&stop,NULL);
	
	if (n < 0) {
		report(0, REPORT_ERROR, "BLOCK4\n");
		pusb_endpoint_close(ep_code);
		return n;
	} else {
		report(1, REPORT_INFO, "BLOCK4 : %6d bytes downloaded : OK", n);
		report(2, REPORT_DEBUG|REPORT_DUMP, "Downloaded in %f ms.\n",
		       buf,
		       n,
		       (double)(stop.tv_sec -start.tv_sec) * 1000.0 +
		       (double)(stop.tv_usec - start.tv_usec) / 1000.0);
	}

	pusb_endpoint_close(ep_code);

	return(0);

}

/*
* Function      : get_reference
* Return Values : <0 on error, >0 on success
* Description   : Retrieves modem serial number
*/
static int get_reference(pusb_device_t fdusb)
{

	char buf[0xe];
	int i,n;
	
	/*
	* URB 151 : this buffer match (if you reverse one byte with its neighbour)
	* the label on the manta box!!! in my case : 3EC18607CAAB06
	* 3EC 18607CAAB 09
	* NB : "My case " == "Benoit's case"
	*/
	
	/* original line */
	n = pusb_control_msg(fdusb,0xc0,0x26,0xf7,0,buf,sizeof(buf),CTRL_TIMEOUT);
	if (n<0)
		report(0, REPORT_ERROR, "get_reference: pusb_control_msg\n");
	else {
	
		char temp[128];

		for (i=0;i<n;i++) {
			int idx = ((i%2)==0) ? i+1 : i-1;
			temp[i] = give_char(buf[idx]);
		}

		temp[n] = '\0';

		report(1, REPORT_INFO, "Modem reference : %s\n", temp);

	}

	return(n);

}

/*
* Function      : modem_start_synchro
* Return Values : -1 on error, 0 on success
* Description   : This function initiates the modem synchronisation
*/
static int modem_start_synchro(pusb_device_t fdusb)
{

	unsigned char buf[2];
	int n;

	n = pusb_control_msg(fdusb,0xc0,0x12,0x04,0x00,buf,sizeof(buf),CTRL_TIMEOUT);

	if (n < 0) {
		report(0, REPORT_ERROR, "modem_start_synchro: pusb_control_msg");
		return(-1);
	}

	report(2, REPORT_DEBUG|REPORT_DUMP, "modem_start_synchro :",
	       buf,
	       n);

	return(0);

}


/*
* Function      : swbuff ON/OFF
* Return Values : None
* Description   : Enables/disables software buffering
*                 Courtesy of Thomson Multimedia
*/  
static void swbuff(pusb_device_t fdusb, int state)
{
   int n;

   n = pusb_control_msg(fdusb,0x40,0x32,state?0x01:0x00,0x00,NULL,0,100);

   report(0, n<0 ? REPORT_ERROR : REPORT_INFO, 
          state ? "Enabling SW buffering\n" : "Disabling SW buffering\n");
 }

/*
* Function      : get_state
* Return Values : -1 is returned on errors, 0 otherwise
* Description   : Retrieves modem state from the usb interrupt end point
* NB            : buf MUST BE at least 15 bytes.
*/
static int get_state(pusb_device_t fdusb, unsigned char *buf)
{

	int ret;

	memset(buf,0,TOTAL);

	ret=pusb_control_msg(fdusb,0xc0,0x12,0x07,0x00,buf+OFFSET_7,SIZE_7,CTRL_TIMEOUT);
	if (ret<0) return(ret);

	ret=pusb_control_msg(fdusb,0xc0,0x12,0x0b,0x00,buf+OFFSET_b,SIZE_b,CTRL_TIMEOUT);
	if (ret<0) return(ret);

	ret=pusb_control_msg(fdusb,0xc0,0x12,0x0d,0x00,buf+OFFSET_d,SIZE_d,CTRL_TIMEOUT);
	if (ret<0) return(ret);

	ret=pusb_control_msg(fdusb,0xc0,0x01,0x0e,0x00,buf+OFFSET_e,SIZE_e,CTRL_TIMEOUT);
	if (ret<0) return(ret);

	ret=pusb_control_msg(fdusb,0xc0,0x01,0x0f,0x00,buf+OFFSET_f,SIZE_f,CTRL_TIMEOUT);
	if (ret<0) return(ret);

	return(0);

}

/*
* Function      : test_sequence
* Return Values : None
* Description   : This a magic sequence, totaly unknown to me [benoit],
*                 it comes from the Windows driver ... 
*/
static void test_sequence(pusb_device_t fdusb)
{

	unsigned char buf[10];
	int n;

	/* URB 147 */
	buf[0] = 0x1c; buf[1] = 0x50;
	n = pusb_control_msg(fdusb,0x40,0x01,0x0b,0x00,buf,2,100);
	if (n<0)
		report(0, REPORT_ERROR, "URB147\n");

	/* URB 148 */
	buf[0] = 0x32; buf[1] = 0x00;
	n = pusb_control_msg(fdusb,0x40,0x01,0x02,0x00,buf,2,100);
	if (n<0)
		report(0, REPORT_ERROR,"URB148\n");

	/* URB 149 */
	buf[0] = 0x01; buf[1] = 0x00; buf[2] = 0x01;
	n = pusb_control_msg(fdusb,0x40,0x01,0x03,0x00,buf,3,100);
	if (n<0)
		report(0, REPORT_ERROR, "URB149\n");
	
	/* URB 150 */
	buf[0] = 0x01; buf[1] = 0x00; buf[2] = 0x01;
	n = pusb_control_msg(fdusb,0x40,0x01,0x04,0x00,buf,3,100);
	if (n<0)
		report(0, REPORT_ERROR, "URB150\n");

}

/*
* Function      : print_state
* Return Values : 0
* Description   : Print a readale modem state
* NB            : buf MUST be 15 bytes long
*/
static int print_state(unsigned char *buf)
{
	time_t t = time(NULL);
	int down_speed = 0, up_speed = 0;
	
	report(2, REPORT_DEBUG,"Modem State\n",ctime(&t));
	report(2, REPORT_DEBUG|REPORT_DUMP,"c0 12 0007 : ", buf+OFFSET_7,SIZE_7);
	report(2, REPORT_DEBUG|REPORT_DUMP,"c0 12 000b : ", buf+OFFSET_b,SIZE_b);
	report(2, REPORT_DEBUG|REPORT_DUMP,"c0 12 000d : ", buf+OFFSET_d,SIZE_d);
	report(2, REPORT_DEBUG|REPORT_DUMP,"c0 01 000e : ", buf+OFFSET_e,SIZE_e);
	report(2, REPORT_DEBUG|REPORT_DUMP,"c0 01 000f : ", buf+OFFSET_f,SIZE_f);
	
	switch (buf[OFFSET_7]) {
	case 0x00:
		report(1, REPORT_INFO, "ADSL line is down\n");
		break;
	case 0x08:
		report(1, REPORT_INFO, "ADSL line is blocked?\n");
		break;
	case 0x10:
		report(1, REPORT_INFO, "ADSL line is synchronising\n");
		break;
	case 0x20:
		down_speed = buf[OFFSET_b] | (buf[OFFSET_b+1]<<8)
			| (buf[OFFSET_b+2]<<16) | (buf[OFFSET_b+3]<<24);
		up_speed = buf[OFFSET_b+4] | (buf[OFFSET_b+5]<<8)
			| (buf[OFFSET_b+6]<<16) | (buf[OFFSET_b+7]<<24);
		
	        if(	((down_speed & 0x0000ffff) == 0) &&
		((up_speed & 0x0000ffff) == 0)) {

		     down_speed>>=16;
		     up_speed>>=16;

	        } 

		report(0, REPORT_INFO, "ADSL line is up (%d kbit/s down | %d kbit/s up)\n",down_speed,up_speed);
		break;
	}
	
	return(0);

}

/*
* Function      : fork_interrupt_daemon
* Return Values : None
* Description   : This function handles the interrupt endpoint in a child
*                 process  and returns immediately.
*
*                 6 bytes are received when the line goes UP : a1 00 01 00 00 00
*                 6 bytes are received for DOWN              : a1 00 00 00 00 00
*/
static void fork_interrupt_daemon(pusb_device_t fdusb)
{

	pid_t child_pid;

	fflush(stdout);
	fflush(stderr);

	if ((child_pid=fork ()) == 0) {

		int up;
		unsigned char state[TOTAL];
		pusb_endpoint_t ep_int;
        int m_id;

        m_id = mutex_init(MUTEX_ID, S_INIT);

		/* Open the "interrupt" endpoint */
		ep_int = pusb_endpoint_open(fdusb, EP_INT, O_RDONLY);
		
		if (ep_int == NULL) {
			report(0, REPORT_ERROR, "pusb_endpoint_open EP_INT\n");
			exit(-1);
		}

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) 
		/*
		 * BUG: unless we close the control endpoint, pppoa will
		 *      not be able to open the device.
		 */
		pusb_close(fdusb);
#endif

		up = 0;
		memset(state, 0, TOTAL);

		while(1) {

			int ret, signaled_kernel;
			unsigned char lbuf[6];

			/* We can try reading the int endpoint */
			ret = pusb_endpoint_read(ep_int, lbuf, sizeof(lbuf), 0);
			
			/* Ok we failed, perhaps the device has been disconnected  */
			if(ret < 0 && errno == ENODEV) {
				report(0, REPORT_INFO, "Device disconnected, shutting down");
                mutex_setval(m_id, S_INIT);
				break;
			}

			/* Just a failure -- report the error and then wait in the waiting loop */
			if(ret < 0)
				report(0, REPORT_ERROR, "Error reading interrupts\n");

			/* Perhaps the reading is a success, in this case the buffer is 6 bytes
			 * long and the content of the buffer is the line state as described
			 * in the two arrays up_int and down_int. */
			signaled_kernel = 0;
			if(ret >= 6) {

				/* The magic interrupt for "up state" */
				char up_int[6]   = { 0xa1, 0x00, 0x01, 0x00, 0x00, 0x00};
				/* The magic interrupt for "down state" */
				char down_int[6] = { 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00};

				if(!memcmp(up_int, lbuf, 6)) {
					if(signal_kernel) {
						sleep(1);
						pusb_ioctl(fdusb, 1, 1, NULL);
						signaled_kernel = 1;
					}
				}

				if(!memcmp(down_int, lbuf, 6)) {
					if(signal_kernel) {
						sleep(1);
						pusb_ioctl(fdusb, 1, 2, NULL);
						signaled_kernel = 1;
					}
				}
	
			}

			/* In all cases, poll the device state */
			ret = poll_state(fdusb, state);
			
			if (ret == 1) {
				report(0, REPORT_INFO, "[monitoring report] ADSL link went up\n");
				up = 1;
			} else if (ret == -1) {
				report(0, REPORT_INFO, "[monitoring report] ADSL link went down\n");
				up = 0;
			} else {
				report(0, REPORT_INFO, "[monitoring report] ADSL link stays stable (%s)\n", (up)?"up":"down");
			}

			/* If the kernel hasn't yet been signaled the current
			 * device state, do it now thanks to the informations
			 * obtained by the polling (unlike interrupt data,
			 * state polling can be trusted) */
			if (signal_kernel && !signaled_kernel) {
				sleep(1);
				pusb_ioctl(fdusb, 1, (up)?1:2, NULL);
			}
		}

		pusb_endpoint_close(ep_int);

		exit(-1);

	}

}

/*
* Function      : poll_state
* Return Values : -1 the link went down
*                  0 no link state change
*                  1 the link went up
* Description   : This function polls the device and according to the previous
*                 state "context", returns whether the link has gone
*                 up/down/unchanged. It saves current state context in the
*                 passed prev_state before returning.
*/
static int poll_state(pusb_device_t fdusb, unsigned char *prev_state)
{
	int ret = 0;
	unsigned char state[TOTAL+1000];
	/* TOTAL bytes are useful, but in case get_state writes more than we
	 * really need, add 1000 to be safe */

	/* Get the state from the device */
	get_state(fdusb, state);
			
	/* Compare the current state against the old one to see if the link
	 * has went down/up */
	if(memcmp(state, prev_state, TOTAL)) {
		/* Ok the line is UP */
		if(state[OFFSET_7] == 0x20 && prev_state[OFFSET_7] != 0x20)
			ret = 1;
		/* Bad the line is down */
		if(state[OFFSET_7] != 0x20 && prev_state[OFFSET_7] == 0x20)
			ret = -1;

		/* Copy new buffer into the previous one */
		memcpy(prev_state, state, TOTAL);
	}
	return(ret);
}

static void signal_alrm(int signal)
{
        /* Connection attempt timed out */
	timed_out = 1;
}

static void signal_usr1(int sig)
{
    /*
      SIGUSR1 is used by our child process to tell use that we need
      to exit with code 0
    */

    exit (0);
}

/*****************************************************************************
*	Logging
*****************************************************************************/

void report( int minlevel, unsigned int flags, const char *format, ...)
{


	va_list ap;
	int length = 0;
	char *buffer = NULL;


	if( verbose >= minlevel ) {
#ifdef USE_SYSLOG
		char msg[256];
#endif

		/* if log is null, try to open the log file */
		if(flog == NULL) {

#ifndef USE_SYSLOG
			flog = stderr;

			/* set raw mode */
			setbuf(flog, NULL);
#else
			openlog("modem_run", LOG_PID, LOG_USER);
			flog = (FILE*)0xcafecafe;
#endif

		}

		va_start(ap, format);

#ifndef USE_SYSLOG
		/* prints date */
		if(flags & REPORT_DATE) {
			time_t tps;
			time(&tps);
			fprintf(flog, "[%.24s] ", ctime(&tps));
		}


		if(flags&REPORT_ERROR)
			fprintf(flog, "Error ");
		else if (flags&REPORT_INFO)
			fprintf(flog, "Info  ");
		else if (flags&REPORT_DEBUG)
			fprintf(flog, "Debug ");

#endif

		/* Store the buffer we need to hexdump and its size */
		if(flags & REPORT_DUMP) {
			buffer = va_arg(ap, char*);
			length = va_arg(ap, int);
		}

#ifndef USE_SYSLOG
		vfprintf(flog, format, ap);
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
			fprintf(flog, "Reason : %s\n", strerror(errno));
#endif

		if(flags & REPORT_DUMP)
			dump(buffer, length);

		va_end(ap);

	}

	return;

}

static void report_stop()
{

#ifdef USE_SYSLOG
	closelog();
#endif

	flog = NULL;

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
	if(flog == NULL)
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
			fprintf(flog, "%02x ", buf[j]);
#else
			sprintf(ptr, "%02x ", buf[j]);
			ptr += 3;
#endif
		}

		for(; j < i + 16; j++) {
#ifndef USE_SYSLOG
			fprintf(flog, "   ");
#else
			sprintf(ptr, "   ");
			ptr += 3;
#endif
		}

		for(j = i; j < len && j < i + 16; j++) {
#ifndef USE_SYSLOG
			fprintf(flog, "%c", give_char(buf[j]));
#else
			sprintf(ptr, "%c", give_char(buf[j]));
			ptr++;
#endif
		}

#ifndef USE_SYSLOG
		fprintf(flog, "\n");
#else
		*ptr = '\0';
		syslog(LOG_DEBUG, line);
#endif

	}
	
#ifndef USE_SYSLOG
	fprintf(flog, "\n");
#endif
}

#endif /* _MODEM_RUN_C_*/
