/* 
 * horch - simple CAN bus analyzer, Header
 *
 * Copyright (c) 1999-2001 port GmbH, Halle
 *------------------------------------------------------------------
 * $Header: /cvs/sw/new-wave/user/horch/horch.h,v 1.1 2003-07-18 00:11:46 gerg Exp $
 *
 *--------------------------------------------------------------------------
 *
 *
 * modification history
 * --------------------
 * $Log: horch.h,v $
 * Revision 1.1  2003-07-18 00:11:46  gerg
 * I followed as much rules as possible (I hope) and generated a patch for the
 * uClinux distribution. It contains an additional driver, the CAN driver, first
 * for an SJA1000 CAN controller:
 *   uClinux-dist/linux-2.4.x/drivers/char/can4linux
 * In the "user" section two entries
 *   uClinux-dist/user/can4linux     some very simple test examples
 *   uClinux-dist/user/horch         more sophisticated CAN analyzer example
 *
 * Patch submitted by Heinz-Juergen Oertel <oe@port.de>.
 *
 *
 *
 *
 *
*/



#ifndef TRUE
# define TRUE  1
# define FALSE 0
#endif

#define PIDFILE "/var/run/horch.pid"

#define LOGFILE		"logfile"	/* file name for record log */
#define TESTCOB		0x672		/* ID of debug messages */
#define MAX_CLINE	100		/* max length of input line */

#define BDEBUG	if(debug) printf

#include <stdio.h>

#if defined(TARGET_LINUX_PPC) || defined(TARGET_LINUX_COLDFIRE) || defined(CONFIG_COLDFIRE)
#define TARGET_LINUX
#endif

/*---------------------------------------------------------------*/
#if defined(TARGET_LINUX)
/*---------------------------------------------------------------*/
# include <errno.h>
# include <stdlib.h>
# include <string.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <sys/time.h>
# include <sys/ioctl.h>
# include <unistd.h>
# include <fcntl.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <signal.h>

/*---------------------------------------------------------------*/
# if defined(LINUX_ARM) || defined(CPC_LINUX) 
/*---------------------------------------------------------------*/
   /* cpc driver */
#  define CAN_MSG_LENGTH 8                /**< maximum length of a CAN frame */

#  define MSG_RTR	(1<<0)          /**< RTR Message */
#  define MSG_OVR	(1<<1)          /**< CAN controller Msg overflow error */ 
#  ifndef MSG_EXT
#   define MSG_EXT	(1<<2)          /**< extended message format */
#  endif
#  define MSG_PASSIVE	(1<<4)          /**< controller in error passive */
#  define MSG_BUSOFF	(1<<5)          /**< controller Bus Off  */
#  define MSG_		(1<<6)          /**<  */
#  define MSG_BOVR	(1<<7)          /**< receive/transmit buffer overflow */

/**
* mask used for detecting CAN errors in the canmsg_t flags field
*/
#  define MSG_ERR_MASK	(MSG_OVR + MSG_PASSIVE + MSG_BUSOFF + MSG_BOVR)


#  define STDDEV		""

typedef int SOCKET;

typedef struct {
	int flags;
	int cob;
	unsigned long id;
	struct timeval timestamp;
	short int length;
	unsigned char data[CAN_MSG_LENGTH];

} canmsg_t;

#  define CONFIG_EXTENDED_IDENTIFIER 1

int	set_bitrate( char *line );
int	set_acceptance( char *line );
/*---------------------------------------------------------------*/
# else /* defined(LINUX_ARM) || defined(CPC_LINUX) */
/*---------------------------------------------------------------*/
   /* can4linux driver */
#  include <can4linux.h>

typedef void sigfunc(int);
sigfunc *signal (int, sigfunc *);

typedef struct  {
   struct timeval it_interval;
   struct timeval it_value;
} itimerval;


# ifndef MSG_EXT
#  define MSG_EXT	(1<<2)
# endif

# define STDDEV		"/dev/can0"

typedef int SOCKET;

/*---------------------------------------------------------------*/
# endif /* defined(LINUX_ARM) || defined(CPC_LINUX) */
#endif /* defined(TARGET_LINUX) */
/*---------------------------------------------------------------*/



/*---------------------------------------------------------------*/
#if defined(TARGET_LX_WIN_BC) || defined(TARGET_AC2_WIN_BC)\
    || defined(TARGET_CPC_WIN_BC)
/*---------------------------------------------------------------*/

#include <stdlib.h>
#include <windows.h>
#include <mmsystem.h>
#include <winsock.h>
#include <time.h>
#include <dos.h>

#define CAN_MSG_LENGTH 8                /**< maximum length of a CAN frame */

#define MSG_RTR		(1<<0)          /**< RTR Message */
#define MSG_OVR		(1<<1)          /**< CAN controller Msg overflow error */ 
#ifndef MSG_EXT
# define MSG_EXT	(1<<2)          /**< extended message format */
#endif
#define MSG_PASSIVE	(1<<4)          /**< controller in error passive */
#define MSG_BUSOFF	(1<<5)          /**< controller Bus Off  */
#define MSG_		(1<<6)          /**<  */
#define MSG_BOVR	(1<<7)          /**< receive/transmit buffer overflow */

/**
* mask used for detecting CAN errors in the canmsg_t flags field
*/
#define MSG_ERR_MASK	(MSG_OVR + MSG_PASSIVE + MSG_BUSOFF + MSG_BOVR)


#define STDDEV		""

/* typedef int SOCKET; */

typedef struct {
	int flags;
	int cob;
	unsigned long id;
	struct timeval timestamp;
	short int length;
	unsigned char data[CAN_MSG_LENGTH];

} canmsg_t;

/* #define SIM 1 */
#if defined(TARGET_CPC_ECO_WIN_BC)
# define CONFIG_EXTENDED_IDENTIFIER 1
#endif

int	set_bitrate( char *line );
int	set_acceptance( char *line );
/*---------------------------------------------------------------*/
#endif /* TARGET_xxx_WIN_BC */
/*---------------------------------------------------------------*/

/*---------------------------------------------------------------*/
#ifdef TARGET_IPC
/*---------------------------------------------------------------*/
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <conio.h>
#include <ipc/sys/socket.h>


#define STDDEV		"SJA1000"	/* only text */

#define CAN_MSG_LENGTH 8
#define MSG_RTR		(1<<0)		/**< RTR Message */
#define MSG_OVR		(1<<1)		/**< CAN controller Msg overflow error */
#define MSG_EXT		(1<<2)		/**< extended message format */
#define MSG_PASSIVE	(1<<4)		/**< controller in error passive */
#define MSG_BUSOFF      (1<<5)		/**< controller Bus Off  */
#define MSG_       	(1<<6)		/**<  */
#define MSG_BOVR	(1<<7)		/**< receive/transmit buffer overflow */
/**
* mask used for detecting CAN errors in the canmsg_t flags field
*/
#define MSG_ERR_MASK	(MSG_OVR + MSG_PASSIVE + MSG_BUSOFF + MSG_BOVR)


typedef int SOCKET;

struct timeval {
	long int tv_sec;
	long int tv_usec;

};
typedef struct {
	int flags;
	int cob;
	unsigned long id;
	/* struct timeval timestamp; */
        unsigned long timestamp;
	short int length;
	unsigned char data[CAN_MSG_LENGTH];

} canmsg_t;


int getopt ( int argc, char * const *argv, const char *optstring);
/*---------------------------------------------------------------*/
#endif		/* TARGET_IPC */
/*---------------------------------------------------------------*/

/*---------------------------------------------------------------*/
/*---------------------------------------------------------------*/
/*---------------------------------------------------------------*/
extern int debug;
extern int o_focus;
extern int o_server;
extern int o_udpserver;
extern int o_bitrate;
extern int o_portnumber;
extern int o_timestamp;
extern long o_period;
extern int o_show_status;
extern int show_time;
extern unsigned long  interrupts;
extern char device[];
extern char horch_revision[];		/* Makefile generated version.c */
extern SOCKET server_fd;
extern struct sockaddr_in fsin;		/* UDP socket */

extern char send_line[];		/* formatted message */
extern int send_line_cnt;
extern float f_busload;

/* function proto types */
int	set_up(void);
void	event_loop(void);
int	server_event_loop(void);
int	udp_event_loop(void);
void	clean_up(void);
int	show_message(canmsg_t *m);
int	show_system_time(char *line);
int	change_format(char c);
#ifndef __WIN32__
void	Sleep(unsigned int time);
#endif
int	display_line(char *line);	/* send line through socket or not */
void	reset_send_line(void);
#ifdef TARGET_IPC
                   /* nor format flags for extended message */
int	write_message(char *line);	/* write CAN message */
#else
int	write_message(int format, char *line);	/* write CAN message */
#endif
int	set_acceptance(char *line);	/* set CAN register */
void	getStat(char *line);	        /* fill line with status info */

