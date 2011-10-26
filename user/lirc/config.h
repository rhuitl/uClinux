/* config.h.in.  Generated automatically from configure.in by autoheader.  */
/*      $Id: config.h,v 1.2 2002-02-07 00:43:01 pdh Exp $      */

/*
 *  are you editing the correct file?
 *  
 *  acconfig.h  - changes for distribution
 *                you must run autoheader / configure
 *  config.h.in - changes specific to your installation
 *                these will be lost if you run autoheader
 *  config.h    - changes to this configuration
 *                these will be lost if you run configure
 */

/* note.
 * if you want to change silly things like the device file names or the
 * configuration file names then remember you may also need to change
 * the Makefile.am files.
 */

/* device file names - beneath DEVDIR (default /dev) */
#define DEV_LIRC	"lirc"
#define DEV_LIRCD	"lircd"
#define DEV_LIRCM	"lircm"

/* config file names - beneath SYSCONFDIR (default /usr/local/etc) */
#define CFG_LIRCD	"lircd.conf"
#define CFG_LIRCM	"lircmd.conf"

/* config file names - beneath $HOME */
#define CFG_USER	".lircrc"

/* log files */
#define LOGDIR		"/var/log"
#define LOG_LIRCD	"lircd"
#define LOG_LIRMAND	"lirmand"

/* pid file */
#define PIDDIR          "/var/log"
#define PID_LIRCD       "lircd.pid"

/* default port number */
#define	LIRC_INET_PORT	8765

/*
 * below here are defines managed by autoheader / autoconf
 */


/* Define to empty if the keyword does not work.  */
#undef const

/* Define if you don't have vprintf but do have _doprnt.  */
#undef HAVE_DOPRNT

/* Define if you have the vprintf function.  */
#define HAVE_VPRINTF 1

/* Define as __inline if that's what the C compiler calls it.  */
#undef inline

/* Define to `long' if <sys/types.h> doesn't define.  */
#undef off_t

/* Define to `int' if <sys/types.h> doesn't define.  */
#undef pid_t

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define to `unsigned' if <sys/types.h> doesn't define.  */
#undef size_t

/* Define if you have the ANSI C header files.  */
#undef STDC_HEADERS

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#undef TIME_WITH_SYS_TIME

/* Define if your <sys/time.h> declares struct tm.  */
#undef TM_IN_SYS_TIME

/* Define if the X Window System is missing or not being used.  */
#define X_DISPLAY_MISSING 1

/* define in maintainer mode */
#undef MAINTAINER_MODE

/* Define to use long long IR codes */
#undef LONG_IR_CODE

/* Define to enable debugging output */
#define DEBUG 1

/* Define to run daemons as daemons */
#undef DAEMONIZE

/* Define if the caraca library is installed */
#undef HAVE_LIBCARACA

/* Define if the libirman library is installed */
#undef HAVE_LIBIRMAN

/* Define if the software only test version of libirman is installed */
#undef HAVE_LIBIRMAN_SW

/* Define if the complete vga libraries (vga, vgagl) are installed */
#undef HAVE_LIBVGA

/* define if you want to log to syslog instead of logfile */
#define USE_SYSLOG 1

/* Text string signifying which driver is configured */
#define LIRC_DRIVER  "lirc_serial"

/* Set the device major for the lirc driver */
#define LIRC_MAJOR  61

/* Set the IRQ for the lirc driver */
#undef LIRC_IRQ

/* Set the port address for the lirc driver */
#undef LIRC_PORT

/* Set the timer for the parallel port driver */
#undef LIRC_TIMER

/* Set the default tty used by the irman/remotemaster driver */
#undef LIRC_IRTTY

/* Define if you have an animax serial port receiver */
#undef LIRC_SERIAL_ANIMAX

/* Define if you have a IR diode connected to the serial port */
#undef LIRC_SERIAL_TRANSMITTER

/* Define if the software needs to generate the carrier frequency */
#undef LIRC_SERIAL_SOFTCARRIER

/* Define if you have an IRdeo serial port receiver */
#undef LIRC_SERIAL_IRDEO

/* Define if you want to use a Tekram Irmate 210 */
#undef LIRC_SIR_TEKRAM

/* Define if there's no device connected to the local lircd */
#undef LIRC_NETWORK_ONLY

/* syslog facility to use */
#define LIRC_SYSLOG  LOG_DAEMON

/* system configuration directory */
#define SYSCONFDIR  "/etc/config"

/* device files directory */
#define DEVDIR   "/dev"

/* This should only be set by configure */
#define PACKAGE   "lirc"

/* This should only be set by configure */
#define VERSION   "0.6.3"

/* Define if you have the daemon function.  */
#undef HAVE_DAEMON

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the mkfifo function.  */
#define HAVE_MKFIFO 1

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the snprintf function.  */
#define HAVE_SNPRINTF 1

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define if you have the strdup function.  */
#define HAVE_STRDUP 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the strsep function.  */
#define HAVE_STRSEP 1

/* Define if you have the strtoul function.  */
#define HAVE_STRTOUL 1

/* Define if you have the vsyslog function.  */
#define HAVE_VSYSLOG 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <sys/ioctl.h> header file.  */
#define HAVE_SYS_IOCTL_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <syslog.h> header file.  */
#define HAVE_SYSLOG_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Name of package */
// #define PACKAGE "lirc"

/* Version number of package */
// #define VERSION "0.0.0"


/*
 * compatibility and useability defines
 */

/* FIXME */
#ifdef LIRC_HAVE_DEVFS
#define LIRC_DRIVER_DEVICE	DEVDIR "/" DEV_LIRC "/0"
#else
#define LIRC_DRIVER_DEVICE      DEVDIR "/" DEV_LIRC
#endif /* LIRC_HAVE_DEVFS */

#define LIRCD			"/var/tmp/" DEV_LIRCD
#define LIRCM			"/var/tmp/" DEV_LIRCM

#define LIRCDCFGFILE		SYSCONFDIR "/" CFG_LIRCD
#define LIRCMDCFGFILE		SYSCONFDIR "/" CFG_LIRCM

#define LIRCCFGFILE		CFG_USER

#define LOGFILE			LOGDIR "/" LOG_LIRCD
#define LIRMAND_LOGFILE		LOGDIR "/" LOG_LIRMAND

#define PIDFILE                 PIDDIR "/" PID_LIRCD

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

/* end of acconfig.h */
