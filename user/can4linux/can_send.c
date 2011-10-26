/* can driver
*  test programm
*  send messages commissioned via command line
* 
* To do:
* - weitere testsequencen
* - steuerung der Bitrate beim Start
* - -debug schaltet mit debug level auch Treiber in debug mode
* - ..
* - Konfiguration über config-datei
* - nanosleep() siehe test3()
*/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
/* #include <sys/time.h> */
#include <time.h>
#include <sys/ioctl.h>

#ifdef USE_RT_SCHEDULING
# include <sched.h>
# include <sys/mman.h>
#endif

#include <errno.h>
#include "can4linux.h"

#define    DEBUG_NONE  ioctl(can_fd, CAN_DEBUG_LEVEL, CAN_DEBUG_NONE)
#define    DEBUG_SOME  ioctl(can_fd, CAN_DEBUG_LEVEL, CAN_DEBUG_SOME)
#define    DEBUG_ALL   ioctl(can_fd, CAN_DEBUG_LEVEL, CAN_DEBUG_ALL)

#define STDDEV "/dev/can1"
#define VERSION "1.6"

#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif

extern int errno;
canmsg_t message;
void sbuf(unsigned char *s, int n);
void usage(char *s);
int can_fd;
int node                 = 8;
int debug                = FALSE;
int extd                 = FALSE;
int load		 = 50;		/* default bus-load */
int doload		 = FALSE;		/* default bus-load */
int stresstest           = FALSE;
int testtype             = 1;  
int sleeptime            = 0;		/* single message */
int cstdout              = FALSE;	/* use stdout for CAN message */
long int test_count_soll = 0;
int rtr                  = FALSE;
int baud		 = -1;		/* dont change baud rate */
int priority		 = -1;		/* dont change priority rate */
int canreset		 = FALSE;
int mask                 = 0;
/* functions */
void clean_process(void);
void test1(void);
void test2(void);
void test3(void);
void test10(void);
void test11(void);
void test12(void);
void test20(void);

/***********************************************************************
*
* set_bitrate - sets the CAN bit rate
*
*
* Changing these registers only possible in Reset mode.
*
* RETURN:
*
*/

int	set_bitrate(
	int fd,			/* device descriptor */
	int baud		/* bit rate */
	)
{
Config_par_t  cfg;
volatile Command_par_t cmd;


    cmd.cmd = CMD_STOP;
    ioctl(fd, COMMAND, &cmd);

    cfg.target = CONF_TIMING; 
    cfg.val1   = baud;
    ioctl(fd, CONFIG, &cfg);

    cmd.cmd = CMD_START;
    ioctl(fd, COMMAND, &cmd);
    return 0;
}

/*  */
void getStat(void)
{
CanStatusPar_t status;
    ioctl(can_fd, STATUS, &status);
    printf(":: %02x %d %d %d %02x | %d | r%d t%d\n",
    	status.status,
    	status.error_warning_limit,
    	status.rx_errors,
    	status.tx_errors,
    	status.error_code,
    	status.rx_buffer_size,
    	status.rx_buffer_used,
    	status.tx_buffer_used
    	);
}

int set_mask( int fd )
{

int ret;
Config_par_t  cfg;

    cfg.target = CONF_ACCM; 
    cfg.val1   = 0xffffffff; /* mask */
    cfg.val2   = 0xffffffff; /* mask */

    ret = ioctl(fd, CONFIG, &cfg);

    return ret;
}

int can_reset( void ) {

int ret;
volatile Command_par_t cmd;


    cmd.cmd = CMD_RESET;
    ret = ioctl(can_fd, COMMAND, &cmd);

    return ret;
}

/**
*
* The main program
*
*/
int main(int argc, char **argv)
{
int ret;
int cnt;
int c;
char *pname;
extern char *optarg;
extern int optind, opterr, optopt;
char device[40] = STDDEV;
int max_priority;
int increment = 0;

    pname = *argv;

#ifdef USE_RT_SCHEDULING
    max_priority = sched_get_priority_max(SCHED_RR) - 1;
#else 
    max_priority = 1;
#endif

    /* our default 8 byte message */
    message.id      = 100;
    message.cob     = 0;
    message.flags   = 0;
    message.length  = 8;
    message.data[0] = 0x55;
    message.data[1] = 2;
    message.data[2] = 3;
    message.data[3] = 4;
    message.data[4] = 5;
    message.data[5] = 6;
    message.data[6] = 7;
    message.data[7] = 0xaa;

    while ((c = getopt(argc, argv, "b:dehl:rp:s:mn:D:t:T:VR")) != EOF) {
	switch (c) {
	    case 'r':
		rtr = TRUE;
		break;
	    case 'e':
		extd = TRUE;
		break;
	    case 'b':
		baud = atoi(optarg);
		break;
	    case 'l':
		load = atoi(optarg);
		doload = TRUE;
		break;
#ifdef USE_RT_SCHEDULING
	    case 'p':
	        {
	        struct sched_param mysched;
		    priority = atoi(optarg);
		    if (priority < 0 ) {
		      fprintf(stderr, "Priority < 0 not allowed\n");
		    }
		    if (priority > max_priority) {
		      fprintf(stderr, "Priority > %d not allowed\n",
		      					max_priority);
		    }
		    mysched.sched_priority =
		    		sched_get_priority_max(SCHED_RR) - 1;
		    ret = sched_setscheduler(0,SCHED_FIFO,&mysched);
		    if ( debug == TRUE ) {
			printf("sched_setscheduler() = %d\n", ret);
		    }
		    /* lock all currently and in future
			allocated memory blocks in physical ram */
		    ret = mlockall(MCL_CURRENT | MCL_FUTURE);
		    if ( debug == TRUE ) {
			printf("mlockall() = %d\n", ret);
		    }
		}
		break;
#endif
	    case 's':
		sleeptime = atoi(optarg);
		break;
	    case 'm':
		mask = 1;
		break;
	    case 'n':
		node = atoi(optarg);
		sprintf(device, "/dev/canp%d", node);
		break;
	    case 'D':
	        if (0 == strcmp(optarg, "stdout")) {
	            cstdout = TRUE;
	        } else {
		    sprintf(device, "/dev/%s", optarg);
		}
		break;
	    case 'd':
		debug = TRUE;
		break;
	    case 't':
		stresstest = TRUE;
		testtype   = atoi(optarg);
		break;
	    case 'T':
		test_count_soll = atoi(optarg);
		break;
	    case 'V':
		printf("can_send V " VERSION ", " __DATE__ "\n");
		exit(0);
		break;
	    case 'R':
		canreset = TRUE;
		break;
	    case 'h':
	    default: usage(pname); exit(0);
	}
    }


    if ( argc - optind > 0 ) {
        /* at least one additional argument, the message id is given */
	message.id =  strtol(argv[optind++], NULL, 0);
    	memset(message.data, 0, 8);
	message.length = 0;
    }
    if ( argc - optind > 0 ) {
    	/* also data bytes areg given with the command */
	cnt = 0;
	while(optind != argc && cnt < 8) {
	    message.data[cnt++] = strtol(argv[optind++], NULL, 0);
	}
	message.length = cnt;
    }
    if (rtr) {
	message.flags |= MSG_RTR;
    }
    if (extd) {
	message.flags |= MSG_EXT;
    }

    if ( debug == TRUE ) {

	printf("can_send V " VERSION ", " __DATE__ "\n");
	printf("(c) 1996-2003 port GmbH\n");
	printf(" using canmsg_t with %d bytes\n", sizeof(canmsg_t));
	printf(" max process priority is \"-p %d\"\n", max_priority);
	if (stresstest) {
	    printf("should send one of the test sequences\n");
	} else {
	    printf("should send mess %ld with: %s", message.id,
		message.length > 0 ? ": " : "out data");
	    sbuf(message.data, message.length);
	}
    }

    sleeptime *= 1000;
    if ( debug == TRUE ) {
	printf("Sleeptime between transmit messages= %d us\n", sleeptime);
    }
    srand(node * 100);

    if (cstdout == FALSE) {
        /* really use CAN, open the device driver */
	if ( debug == TRUE ) {
	    printf("Open device %s\n", device);
	}
        if(!mask) 
	    can_fd = open(device, O_WRONLY);
	else
            can_fd = open(device, O_RDWR);
	if (can_fd == -1) {
	    fprintf(stderr, "open error %d;", errno);
	    perror(device);
	    exit(1);
	}

	if ( canreset == TRUE ) {
	    ret = can_reset();
	    if ( ret == -1 ) {
		perror("CAN Reset");
		exit(EXIT_FAILURE);
	    }
	    if ( debug == TRUE) {
		printf("Reset successfull\n");
	    }
	    exit(EXIT_SUCCESS);
	}
	
	if (baud > 0) {
	    if ( debug == TRUE ) {
		printf("change Bit-Rate to %d Kbit/s\n", baud);
	    }
	    set_bitrate(can_fd, baud);
	}
    } else {
	can_fd = 1;		/* use stdout */
    }
    if ( debug == TRUE ) {
	printf("opened %s succesful, got can_fd = %d\n", device, can_fd);
    }

    if (doload == TRUE) {
	test20();
	exit(0);
    }
    if (stresstest) {
	switch(testtype) {
	    case 1:  test1(); exit(0); break;
	    case 2:  test2(); exit(0); break;
	    case 3:  test3(); exit(0); break;
	    case 4:  increment = 1; break;
	    case 10: test10(); exit(0); break;
	    case 11: test11(); exit(0); break;
	    case 12: test12(); exit(0); break;
	    default:
	    fprintf(stderr, "test type %d is not defined\n", testtype); break;
	    exit(0); break;
	}
    }

    /* else */
    /* the default can_send, simply send a message */
    /* no special test, send the normal message, (old behaviouur) */
    do {
        if ( debug == TRUE ) {
	     printf(" transmit message %ld\n", message.id ); 
	}
	ret = write(can_fd, &message, 1);
	if (ret == -1) {
	    /* int e = errno; */
	    perror("write error");
	    /* if ( e == ENOSPC) { */
		usleep(sleeptime); 
		continue;
	    /* } */
	} else if (ret == 0) {
	    printf("transmit timed out\n");
		usleep(sleeptime); 
		continue;
	} else {
	}
	if ( debug == TRUE ) {
	     getStat();
 	}
	if (sleeptime > 0) usleep(sleeptime);
	message.id += increment;
    }
    while(sleeptime > 0);


    if (sleeptime == 0) {
        /* do not close while the controller is sending a message
         * sleep() then close()
         */
        usleep(50000);
        /* sleep(1); */
    }
    ret = close(can_fd);
    if (ret == -1) {
	fprintf(stderr, "close error %d;", errno);
	perror("");
	exit(1);
    }
    if ( debug == TRUE ) {
	printf("closed fd = %d succesful\n", can_fd);
    }
    return 0;
}


/* show buffer in hex */
void sbuf(unsigned char *s, int n)
{
int i;

    for(i = 0; i< n; i++) {
	fprintf(stdout, "%02x ", *s++);
    }
    putchar('\n');
}



void usage(char *s)
{
static char *usage_text  = "\
 ist optional id nicht angegeben wird 100 benutzt\n\
 sind keine Daten angegeben, werden max 8 ausgegeben\n\
 eingabe dezimal 100 or hex 0x64\n\
-r send message as rtr message.\n\
-e send message in extended message format.\n\
-l load try to reach this bus load, given in %%\n\
-s n - sleeptime between messages in ms, if not specified send single message\n\
-d   - debug On\n\
       schaltet zusaetzlich Debugging im Treiber an/aus\n\
-b baudrate (Standard uses value of /proc/sys/Can/baud)\n\
-D dev use /dev/dev/{can0,can1,can2,can3} (real nodes, std: can1)\n\
"
"\
-t type \n\
   1 Stresstest für Knoten, Sendet Bursts von kurzen rtr messages\n\
   2 sendet bursts von 5 Daten Messages, gleiche ID\n\
   3 sendet bursts von 5 Daten Messages, unterschiedliche ID\n\
     message 5 enthält counter \n\
   4 as without this option, but incremnts CAN-ID with each message\n\
   10 sendet bursts von 9 Daten Messages, für Comm. Verification\n\
   11 send -T number of messages as fast as possible, if transmit buffer\n\
      is full, sleep for -s ms time. time == 0:don't sleep, poll\n\
      after every message the messageid will increment\n\
   12 same as 11\n\
      but the message id is constant and the databytes will be increment\n\
-R   setzt nur CAN Controller zurück, danach exit()\n\
-T   Anzahl der Bursts, Abstand -s n (für -t)\n\
-V   version\n\
\n\
";
    fprintf(stderr, "usage: %s options [id [ byte ..]]\n", s);
    fprintf(stderr, usage_text);


}

/* test1:
   - Data message 8 byte
   - RTR  Message 0 byte
   - RTR  Message 1 byte
   - RTR  Message 2 byte
*/
void test1(void)
{
long int test_count = 0;
canmsg_t tm[4];
int ret;

    tm[0].id = 100;
    tm[0].cob = 0;
    tm[0].length = 8;
    tm[0].flags = 0;
    if (extd) {
	tm[0].flags |= MSG_EXT;
    }
    tm[0].data[0] = 0x55;
    tm[0].data[1] = 2;
    tm[0].data[2] = 3;
    tm[0].data[3] = 4;
    tm[0].data[4] = 5;
    tm[0].data[5] = 6;
    tm[0].data[6] = 7;
    tm[0].data[7] = 0xaa;

    tm[1].id = message.id;
    tm[1].cob = 0;
    tm[1].length = 0;
    tm[1].flags = MSG_RTR;
    if (extd) {
	tm[1].flags |= MSG_EXT;
    }

    tm[2].id = message.id;
    tm[2].cob = 0;
    tm[2].length = 1;
    tm[2].flags = MSG_RTR;
    if (extd) {
	tm[2].flags |= MSG_EXT;
    }

    tm[3].id = message.id;
    tm[3].cob = 0;
    tm[3].length = 2;
    tm[3].flags = MSG_RTR;
    if (extd) {
	tm[3].flags |= MSG_EXT;
    }


    do {
	ret = write(can_fd, &tm[0], 4);
	if (ret == -1) {
	    perror("write error");
	    usleep(sleeptime); 
	    continue;
	} else if (ret == 0) {
	    printf("transmit timed out\n");
	    usleep(sleeptime); 
	    continue;
	} else {
	    if ( debug == TRUE ) {
		printf("transmitted %d\n", ret);
	    }
	}
	if (++test_count == test_count_soll) {
	    break;
	}
	if (sleeptime > 0 )  {
	    usleep(sleeptime);
	}
    }
    while ( sleeptime > 0 );
}

/* test2:
   - Data message 8 byte id= default or command line
   - Data message 8 byte  "
   - Data message 0 byte  "
   - Data message 8 byte  "
   - Data message 4 byte  "
*/
void test2(void)
{
long int test_count = 0;
canmsg_t tm[5];
int ret;
unsigned int cnt = 0;

    tm[0].id = message.id;
    tm[0].cob = 0;
    tm[0].length = 8;
    tm[0].flags = 0;
    if (extd) {
	tm[0].flags |= MSG_EXT;
    }
    tm[0].data[0] = 0x55;
    tm[0].data[1] = 2;
    tm[0].data[2] = 3;
    tm[0].data[3] = 4;
    tm[0].data[4] = 5;
    tm[0].data[5] = 6;
    tm[0].data[6] = 7;
    tm[0].data[7] = 0xaa;

    tm[1].id = message.id;
    tm[1].cob = 0;
    tm[1].length = 8;
    tm[1].flags = 0;
    if (extd) {
	tm[1].flags |= MSG_EXT;
    }
    tm[1].data[0] = 0xaa;
    tm[1].data[1] = 7;
    tm[1].data[2] = 6;
    tm[1].data[3] = 5;
    tm[1].data[4] = 4;
    tm[1].data[5] = 3;
    tm[1].data[6] = 2;
    tm[1].data[7] = 0x55;

    tm[2].id = message.id;
    tm[2].cob = 0;
    tm[2].length = 0;
    tm[2].flags = 0;
    if (extd) {
	tm[2].flags |= MSG_EXT;
    }

    tm[3].id = message.id;
    tm[3].cob = 0;
    tm[3].length = 8;
    tm[3].flags = 0;
    if (extd) {
	tm[3].flags |= MSG_EXT;
    }
    tm[3].data[0] = 0x55;
    tm[3].data[1] = 2;
    tm[3].data[2] = 3;
    tm[3].data[3] = 4;
    tm[3].data[4] = 5;
    tm[3].data[5] = 6;
    tm[3].data[6] = 7;
    tm[3].data[7] = 0xaa;

    tm[4].id = message.id;
    tm[4].cob = 0;
    tm[4].length = 4;
    tm[4].flags = 0;
    *(unsigned int *)&tm[4].data[0] = cnt++;

    if (extd) {
	tm[4].flags |= MSG_EXT;
    }

    do {
	ret = write(can_fd, &tm[0], 5);
	if (ret == -1) {
	    perror("write error");
	    usleep(sleeptime); 
	    continue;
	} else if (ret == 0) {
	    printf("transmit timed out\n");
	    usleep(sleeptime); 
	    continue;
	} else {
	    if ( debug == TRUE ) {
		printf("transmitted %d\n", ret);
	    }
	}

	*(unsigned int *)&tm[4].data[0] = cnt++;
	if (++test_count == test_count_soll) {
	    break;
	}

	if ( sleeptime > 0 ) {
	    usleep(sleeptime);
	}
    }
    while(sleeptime > 0);
}

/* test3:
   - Data message 8 byte id= default or command line
   - Data message 8 byte  "
   - Data message 0 byte  "
   - Data message 8 byte  "
   - Data message 4 byte  "   - data with 4 byte counter
*/
void test3(void)
{
long int test_count = 0;
canmsg_t tm[6];
int ret;
unsigned int cnt = 0;
int i;

struct timespec req;
/* struct timespec rem; */

#define ID_OFFSET 0x10 		/* used for the following messages */

    tm[0].id = message.id;
    tm[0].cob = 0;
    tm[0].length = 8;
    tm[0].flags = 0;
    if (extd) {
	tm[0].flags |= MSG_EXT;
    }
    tm[0].data[0] = 0x11;
    tm[0].data[1] = 2;
    tm[0].data[2] = 3;
    tm[0].data[3] = 4;
    tm[0].data[4] = 5;
    tm[0].data[5] = 6;
    tm[0].data[6] = 7;
    tm[0].data[7] = 0x11;

    tm[1].id = tm[0].id + ID_OFFSET;
    tm[1].cob = 0;
    tm[1].length = 8;
    tm[1].flags = 0;
    if (extd) {
	tm[1].flags |= MSG_EXT;
    }
    tm[1].data[0] = 0x22;
    tm[1].data[1] = 7;
    tm[1].data[2] = 6;
    tm[1].data[3] = 5;
    tm[1].data[4] = 4;
    tm[1].data[5] = 3;
    tm[1].data[6] = 2;
    tm[1].data[7] = 0x22;

    tm[2].id = tm[1].id + ID_OFFSET;
    tm[2].cob = 0;
    tm[2].length = 8;
    tm[2].flags = 0;
    if (extd) {
	tm[2].flags |= MSG_EXT;
    }
    tm[2].data[0] = 0x33;
    for(i=1; i< 7; i++)
        tm[2].data[i] = 0x00;
    tm[2].data[7] = 0x33;

    tm[3].id = tm[2].id + ID_OFFSET;
    tm[3].cob = 0;
    tm[3].length = 8;
    tm[3].flags = 0;
    if (extd) {
	tm[3].flags |= MSG_EXT;
    }
    for(i=0; i< 8; i++)
        tm[3].data[i] = 0x44;

    tm[4].id = tm[3].id + ID_OFFSET;
    tm[4].cob = 0;
    tm[4].length = 8;
    tm[4].flags = 0;
    if (extd) {
	tm[4].flags |= MSG_EXT;
    }
    tm[4].data[0] = 0x55;
    tm[4].data[1] = 2;
    tm[4].data[2] = 3;
    tm[4].data[3] = 4;
    tm[4].data[4] = 4;
    tm[4].data[5] = 3;
    tm[4].data[6] = 2;
    tm[4].data[7] = 0x55;

    tm[5].id = tm[4].id + ID_OFFSET;
    tm[5].cob = 0;
    tm[5].length = 8;
    tm[5].flags = 0;
    if (extd) {
	tm[5].flags |= MSG_EXT;
    }
    tm[5].data[0] = 0x66;
    tm[5].data[1] = 0x26;
    tm[5].data[2] = 0x35;
    tm[5].data[3] = 0x44;
    tm[5].data[4] = 0x53;
    tm[5].data[5] = 0x62;
    tm[5].data[6] = 0x71;
    tm[5].data[7] = 0x66;

#if 1
	/*
	If  the process is scheduled under a real-time policy like
	SCHED_FIFO or SCHED_RR, then pauses of up to 2 ms will  be
	performed as busy waits with microsecond precision.
	*/
	req.tv_sec = sleeptime / (1000*1000);
	req.tv_nsec = (sleeptime % (1000*1000)) * 1000;
	if ( debug == TRUE ) {
	    printf("Sleep %ld.%09ld\n", req.tv_sec, req.tv_nsec);
	}
#endif
    if(mask) set_mask(can_fd);

    do {
	ret = write(can_fd, &tm[0], 6);
	if (ret == -1) {
	    perror("write error");
	    usleep(sleeptime); 
	    continue;
	} else if (ret == 0) {
	    printf("transmit timed out\n");
	    usleep(sleeptime); 
	    continue;
	} else {
	    if ( debug == TRUE ) {
		printf("transmitted %d\n", ret);
	    }
	}

	/* *(unsigned int *)&tm[4].data[0] = cnt++; Don't change the data */
	if (++test_count == test_count_soll) {
	    break;
	}

	if ( debug == TRUE ) {
	    getStat();
	}

	if (sleeptime > 0) {

	    usleep(sleeptime);
    /* Für die Verwendung von nanosleep muss noch etwas getan werden.
       Nanosleep benutzt bei Zeiten < 2 ms eine echte busy loop im kernel,
       d.h. mit "-s 1" geht bei endlosschleifen dann gar nichts mehr
       außer dem großen Roten Knopf am Rechner.
       Falls also implementieren, dann auf kurze Schleifen, max 10 ode
       so begrenzen, damit kann es aber möglich sein mal schnell 
       meherer telegramme hineterinender zu senden, dann wieder usleep()
       nehmen ...
     */
	    /* nanosleep(&req, &rem); */
	}
    }
    while(sleeptime > 0);
}


/* Test 10


You can see the output in hexformat by calling
             +- select test type
             |      +-- send messages to
             |      |        +- number of sequences a 9 messages ( 2 * 9)
             |      |        |     +- time in ms between sequences
             |      |        |     |
$ can_send -t10 -D stdout -T 2 -s 100 | od -t x1 -w32
                                         |   |     |
                                         |   |     +-- 32 bytes per line == 
                                         |   |         one message
                                         |   +-- type hex, one byte
                                         +- use "object dump" for display


*/
#define SEQN	9 /* number of messages for one sequence, one write call */
void update_seq(canmsg_t *m)
{
int i;

    /* calculate next sequence */
    /* first: new message id */
				/* ((2^11)/9)*9 - 1   
				 * ((2*29)/9)*9 - 1
				 */
    if (    ( extd && (m->id > (536870906 - SEQN))) 
	 || (!extd && (m->id > (     2042 - SEQN)))  ) {
	/* reset message id to 0 */
	for (i = 0; i < SEQN; i++) {
	    (m + i)->id = i;
	}
    } else {
	if ( debug == TRUE ) {
	    printf(" new id %ld\n", m->id + SEQN);
	}
	/* not wrapped, increment message id */
	for (i = 0; i < SEQN; i++) {
		(m + i)->id += SEQN;
	}
    }

    /* now update data bytes with counter value */
    for (i = 0; i < SEQN; i++) {
        char *p;
        p = &((m + i)->data[0]);

	*(unsigned long long *)p += 1;
    }
}

void test10(void)
{
long int test_count = 0;
int ret, i;
/* unsigned int cnt = 0; */
int fac = 1;


canmsg_t tm[SEQN] =  {
    /*  f, cob,  id, time,   l,   data[8]                     */
    {  0 ,   0,   0, {0 , 0},  0, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   1, {0 , 0},  1, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   2, {0 , 0},  2, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   3, {0 , 0},  3, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   4, {0 , 0},  4, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   5, {0 , 0},  5, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   6, {0 , 0},  6, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   7, {0 , 0},  7, { 0, 0, 0, 0, 0, 0, 0, 0} }, 
    {  0 ,   0,   8, {0 , 0},  8, { 0, 0, 0, 0, 0, 0, 0, 0} }};

    if (cstdout == TRUE) {
	/* use stdout */
	fac = sizeof(canmsg_t);
    }
    if (extd) {
	/* set the extd flag in all messages */
	for (i = 0; i < SEQN; i++) {
		tm[i].flags |= MSG_EXT;
	}
    }
    if ( debug == TRUE ) {
	printf("using test10 with extd = %s\n", extd ? "TRUE" : "FALSE");
    }

    /* loop forever if sleeptime > 0 */
    do {
        int seq   = SEQN *fac;
        int start = 0;;

	while(seq) {
	    if ( debug == TRUE ) {
		 printf("send %d/%d, ", start, seq);
	    }
	    ret = write(can_fd, &tm[start], seq);
	    if (ret == -1) {
		perror("write error");
		exit(2);
	    } else if (ret == 0) {
		printf("transmit timed out\n");
		usleep(sleeptime); 
		continue;
	    } else {
		if ( debug == TRUE ) {
		    printf("transmitted %d\n", ret);
		}
	    }
	    if ( debug == TRUE ) {
		getStat();
	    }
	    seq -= ret;
	    start += ret;
	    if ( seq >= 0 && sleeptime) {
	    	usleep(10000); 
	    }
	}
	/* is it enough ? than leave loop */
	if (++test_count == test_count_soll) {
	    break;
	}

        update_seq(&tm[0]);

	/* if neccessary sleep */
	if (sleeptime > 0) {
	    usleep(sleeptime);
	}
    }
    while(1);
    /* before closing the driver, give it a chance to transmit
    messages in tx buffer */
    usleep(1000000);
}

/* using the global defined message, that can be changed via command line,
the function tries to reach a specified bus-load
- use 20 ms sleep time or larger for low bus loads
*/
void test20(void)
{
int n, i, test_count;
int run;
int ret;
// int bits;		/* bits per message */

    /* first assume we have only 11 bit and 8 data bytes */
    /* 1 Message = 120 bits */
    /* number of messages for 100 % */
    /* time   / (bits/m   * time_one_bit) */
    n = 20000 / (120 * (1000 / baud));  
    n = n * load / 100;

    test_count = 0;
    printf("send %ld mesages, %d messages  every 20 ms cycle \n",
    	test_count_soll, n);

    /* printf("soll %ld \n", test_count_soll); */
    sleeptime = 19000;
    run = TRUE;
    while(run) {
	for(i = 0; i < n; i++) {
	    ret = write(can_fd, &message, 1);
	    if (ret == -1) {
		perror("write error; ");
	    } else if (ret == 0) {
		printf("Node %d: transmit time out\n", node);
	    } else {
		if ( debug == TRUE ) {
		     printf("Node %d: transmit message %ld\n", node, message.id );
		 }
	    }
	    if (test_count_soll && (++test_count == test_count_soll)) {
		run = FALSE;
		break;
	    }
	    /* printf("  count %d \n", test_count); */
	}
	/* usleep(sleeptime); */
    }

}

void test11(void)
{
canmsg_t message;
long int test_count = 0;
int ret;

    /* our default 8 byte message */
    message.id      = 0;
    message.cob     = 0;
    message.flags   = 0;
    message.length  = 8;
    message.data[0] = 0x55;
    message.data[1] = 2;
    message.data[2] = 3;
    message.data[3] = 4;
    message.data[4] = 5;
    message.data[5] = 6;
    message.data[6] = 7;
    message.data[7] = 0xaa;
    /* else */
    /* the default can_send, simply send a message */
    /* no special test, send the normal message, (old behaviouur) */
    do {
    again:
        if ( debug == TRUE ) {
	     printf(" transmit message %ld\n", message.id );
	 }
	ret = write(can_fd, &message, 1);
	if (ret == -1) {
	    /* int e = errno; */
	    perror("write error");
	    /* if ( e == ENOSPC) { */
		if (sleeptime) { usleep(sleeptime);  }
		/* continue; */
		goto again;
	    /* } */
	} else if (ret != 1) {
	    fprintf(stderr, "transmitted %d from 1\n", ret);
		if (sleeptime) { usleep(sleeptime);  }
		goto again;
	} else {
	}
	if ( debug == TRUE )
	     getStat();
	message.id = message.id++ % 2000;
    }
    while(++test_count != test_count_soll);
    usleep(1000000);
}

void test12(void)
{
long int test_count = 0;
int ret;

    /* message.id      = 0; */ /* default message id */
    message.cob     = 0;
    message.flags   = 0;
    message.length  = 4;
    message.data[0] = 0;
    message.data[1] = 0;
    message.data[2] = 0;
    message.data[3] = 0;
    message.data[4] = 0;
    message.data[5] = 0;
    message.data[6] = 0;
    message.data[7] = 0;
    /* else */
    /* the default can_send, simply send a message */
    /* no special test, send the normal message, (old behaviouur) */
    do {
    	message.data[0] = test_count % 0x100;
    	message.data[1] = (test_count >> 8) % 0x100;
    	message.data[2] = (test_count >> 16) % 0x100;
    	message.data[3] = (test_count >> 24) % 0x100;
    again:
        if ( debug == TRUE ) {
	     printf(" transmit message %ld\n", message.id );
	 }
	ret = write(can_fd, &message, 1);
	if (ret == -1) {
	    /* int e = errno; */
	    perror("write error");
	    /* if ( e == ENOSPC) { */
		if (sleeptime) { usleep(sleeptime);  }
		/* continue; */
		goto again;
	    /* } */
	} else if (ret != 1) {
	    /* fprintf(stderr, "transmitted %d from 1\n", ret); */
		if (sleeptime) { usleep(sleeptime);  }
		goto again;
	} else {
	}
	if ( debug == TRUE )
	     getStat();
    }
    while(++test_count != test_count_soll);
    usleep(1000000);
}
