/*
 * diald.h - Main header file.
 *
 * Copyright (c) 1994, 1995, 1996 Eric Schenk.
 * All rights reserved. Please see the file LICENSE which should be
 * distributed with this software for terms of use.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/termios.h>
#include <sys/bitypes.h>
#include <net/if.h>
#include <netdb.h>

#ifndef __USE_MISC
#define __USE_MISC 1
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_slip.h>

#include <linux/version.h>
#include <config/autoconf.h>
/* This only exists in kernels >= 1.3.75 */
#if LINUX_VERSION_CODE >= 66379
#define HAS_SOCKADDR_PKT
#include <net/if_packet.h>
#define SOCKADDR sockaddr_pkt
#else
#include <sys/socket.h>
#define SOCKADDR sockaddr
#endif

#ifndef USE_BSD_PTYS
#include <pty.h>
#endif

#include "config.h"
#include "fsm.h"
#include "timer.h"
#include "firewall.h"
#include "bufio.h"

#define LOG_DDIAL	LOG_LOCAL2

/* SLIP special character codes */
#define END             0300    /* indicates end of packet */
#define ESC             0333    /* indicates byte stuffing */
#define ESC_END         0334    /* ESC ESC_END means END data byte */
#define ESC_ESC         0335    /* ESC ESC_ESC means ESC data byte */

/* Operation modes */
#define MODE_SLIP 0
#define MODE_PPP 1
#define MODE_DEV 2


/* Dynamic slip interpretation modes */
#define DMODE_REMOTE 0
#define DMODE_LOCAL 1
#define DMODE_REMOTE_LOCAL 2
#define DMODE_LOCAL_REMOTE 3
#define DMODE_BOOTP 4

/* Define DEBUG flags */
#define DEBUG_FILTER_MATCH	0x0001
#define DEBUG_PROXYARP		0x0004
#define DEBUG_VERBOSE		0x0008
#define DEBUG_STATE_CONTROL	0x0010
#define DEBUG_TICK		0x0020
#define DEBUG_CONNECTION_QUEUE	0x0040

/* Define MONITOR flags */
#define MONITOR_STATE		0x0001
#define MONITOR_INTERFACE	0x0002
#define MONITOR_STATUS		0x0004
#define MONITOR_LOAD		0x0008
#define MONITOR_MESSAGE		0x0010
#define MONITOR_QUEUE		0x0020

/*
 * If you choose UNSAFE_ROUTING=0, then by default diald will route all
 * outgoing packets to the proxy device and forward them to the real
 * device by itself. This has the advantage that it gets around a bug
 * in the current production release (1.2.X) linux kernels
 * that causes TCP sessions to lock up if the route is changed while
 * a packet is being retransmitted. However, this introduces quite
 * a bit of overhead on outgoing packets (10-20%). (Note that incoming packets
 * don't go through this process!)
 * If you choose UNSAFE_ROUTING=1, then diald will change the routes anyway.
 * If you are using diald on a machine were there is a single outgoing
 * link this is perfectly safe (I think!), but if diald is being used
 * in an environment where more than one ppp or slip link can be active
 * at a time, then there is a small chance that you can lock up TCP
 * sessions. In particular if the link is terminated (either by diald
 * or by the other end hanging up) when a TCP session is in the middle
 * of retransmitting a packet, then that TCP session can become locked
 * if when the link comes back up it is brought back up on a different
 * ppp or slip device.
 * [NOTE: As of linux 1.3.13, the Linux kernel has been
 *  fixed to allow routing changes under an active TCP retransmit,
 *  so with 1.3.13 and later UNSAFE_ROUTING as the default is perfectly safe.]
 * [NOTE 2: unlike previous versions of diald, this option can now be
 * controlled from the command line or configuration file. See the new
 * options "reroute" and "-reroute".
 */

#define UNSAFE_ROUTING 1	/* do rerouting by default */

/*
 * Originally diald just threw away any packets it received when
 * the link was down. This is OK because IP is an unreliable protocol,
 * so applications will resend packets when the link comes back up.
 * On the other hand the kernel doubles the timeout for TCP packets
 * every time a send fails. If you define BUFFER_PACKETS diald
 * will store packets that come along when the link is down and
 * send them as soon as the link comes up. This should speed up
 * the initial connections a bit.
 */

#define BUFFER_PACKETS 1	/* turn on packet buffering code. */
#ifdef EMBED
#define BUFFER_SIZE 65500	/* smaller to allow for malloc overhead */
#else
#define BUFFER_SIZE 65536	/* size of buffer to store packets */
#endif
#define BUFFER_FIFO_DISPOSE 1	/* dispose of old packets to make room
				 * for new packets if the buffer becomes
				 * full. Without this option new packets
				 * are discarded if there is no room.
				 */
#define BUFFER_TIMEOUT 600	/* Maximum number of seconds to keep a
				 * packet in the buffer. Don't make this
				 * too large or you will break IP.
				 * (Something on the order of 1 hour
				 * probably the maximum safe value.
				 * I expect that the 10 minutes defined
				 * by default should be plenty.
				 */

/*
 * Various timeouts and times used in diald.
 */

#define PAUSETIME 1	/* how many seconds should diald sleep each time
			   it checks to see what's happening. Note that
			   this is a maximum time and that a packet
			   arriving will cut the nap short. */
#define DEFAULT_FIRST_PACKET_TIMEOUT 120
#define DEFAULT_DIAL_DELAY 30
#define DEFAULT_MTU 1500
#define DEFAULT_SPEED 38400

typedef struct monitors {
    struct monitors *next;
    int fd;			/* monitor output fp. */
    int level;			/* Information level requested */
    char *name;
} MONITORS;

/* Configuration variables */

extern char **devices;
extern int device_count;
extern char device[10];
extern char device_node[9];
extern int device_iface;
extern int inspeed;
extern int window;
extern int mtu;
extern int mru;
extern char *connector;
extern char *disconnector;
extern char *orig_local_ip;
extern char *orig_remote_ip;
extern char *local_ip;
extern unsigned long local_addr;
extern char *remote_ip;
extern char *netmask;
extern char *addroute;
extern char *delroute;
extern char *ip_up;
extern char *ip_down;
extern char *acctlog;
extern char *pidlog;
extern char *fifoname;
extern char *lock_prefix;
extern int pidstring;
extern char *run_prefix;
extern char *diald_config_file;
extern char *diald_defs_file;
extern char *path_route;
extern char *path_ifconfig;
extern char *path_bootpc;
extern char *path_pppd;
extern int buffer_packets;
extern int buffer_size;
extern int buffer_fifo_dispose;
extern int buffer_timeout;
extern FILE *acctfp;
extern int call_start_time;
extern int mode;
extern int debug;
extern int modem;
extern int rotate_devices;
extern int crtscts;
extern int dodaemon;
extern int dynamic_addrs;
extern int dynamic_mode;
extern int slip_encap;
extern int lock_dev;
extern int default_route;
extern int pppd_argc;
extern char **pppd_argv;
extern int connect_timeout;
extern int disconnect_timeout;
extern int redial_timeout;
extern int nodev_retry_timeout;
extern int stop_dial_timeout;
extern int kill_timeout;
extern int start_pppd_timeout;
extern int stop_pppd_timeout;
extern int first_packet_timeout;
extern int retry_count;
extern int died_retry_count;
extern int redial_backoff_start;
extern int redial_backoff_limit;
extern int redial_backoff;
extern int dial_fail_limit;
extern int two_way;
extern int give_way;
extern int do_reroute;
extern int proxyarp;
extern int route_wait;
extern int metric;
extern int drmetric;

/* Global variables */

extern int fifo_fd;			/* FIFO command pipe. */
extern MONITORS *monitors;		/* List of monitor pipes. */
extern int proxy_mfd;			/* master pty fd */
extern FILE *proxy_mfp;		/* also have an fp. Hackery for recv_packet. */
extern int proxy_sfd;			/* slave pty fd */
extern int modem_fd;			/* modem device fp (for slip links) */
extern char packet[4096];		/* slip packet buffer */
extern int modem_hup;			/* have we seen a modem HUP? */
extern int request_down;		/* has the user requested link down? */
extern int request_up;			/* has the user requested link up? */
extern int forced;			/* has the user requested the link forced up? */
extern int link_pid;			/* current pppd command pid */
extern int dial_pid;			/* current dial command pid */
extern int running_pid;		/* current system command pid */
extern int dial_status;		/* status from last dial command */
extern int state_timeout;		/* state machine timeout counter */
extern int blocked;			/* user has blocked the link */
extern int state;			/* DFA state */
extern int current_retry_count;	/* current retry count */
extern int proxy_iface;		/* Interface number for proxy pty */
extern int link_iface;			/* Interface number for ppp line */
extern int orig_disc;			/* original PTY line disciple */
extern int fwdfd;			/* control socket for packet forwarding */
extern int snoopfd;			/* snooping socket fd */
extern int fwunit;			/* firewall unit for firewall control */
extern int req_pid;			/* pid of process that made "request" */
extern char *req_dev;			/* name of the device file requested to open */
extern int use_req;			/* are we actually using the FIFO link-up request device? */
extern char snoop_dev[10];		/* The interface name we are listening on */
extern int txtotal,rxtotal;		/* transfer stats for the link */
extern int itxtotal, irxtotal;		/* instantaneous transfer stats */
extern int delayed_quit;		/* has the user requested delayed termination?*/
extern int terminate;			/* has the user requested termination? */
extern int impulse_time;		/* time for current impulses */
extern int impulse_init_time;		/* initial time for current impulses */
extern int impulse_fuzz;		/* fuzz for current impulses */
extern char *pidfile;			/* full path filename of pid file */
extern int force_dynamic;		/* 1 if the current connect passed back addrs */
extern int redial_rtimeout;		/* current real redial timeout */
extern int dial_failures;		/* number of dial failures since last success */
extern int ppp_half_dead;		/* is the ppp link half dead? */

#ifdef SIOCSKEEPALIVE
extern int keepalive;
#endif

#ifdef SIOCSOUTFILL
extern int outfill;
#endif

/* function prototypes */
extern void init_vars(void);
extern void parse_init(void);
extern void parse_options_file(char *);
extern void parse_args(int, char *[]);
extern void check_setup(void);
extern void signal_setup(void);
extern void default_sigacts(void);
extern void block_signals(void);
extern void unblock_signals(void);
extern void filter_setup(void);
extern void get_pty(int *, int *);
extern void proxy_up(void);
extern void proxy_down(void);
extern void proxy_config(char *, char *);
extern void dynamic_slip(void);
extern void idle_filter_proxy(void);
extern void open_fifo(void);
extern void filter_read(void);
extern void fifo_read(void);
extern void proxy_read(void);
extern void modem_read(void);
extern void advance_filter_queue(void);
extern int recv_packet(unsigned char *, int);
extern void sig_hup(int);
extern void sig_intr(int);
extern void sig_term(int);
extern void sig_io(int);
extern void sig_chld(int);
extern void sig_pipe(int);
extern void linkup(int);
extern void die(int);
extern void print_filter_queue(int);
extern void monitor_queue(void);
extern void create_pidfile(int iface);
extern void become_daemon(void);
extern void change_state(void);
extern void output_state(void);
extern void add_device(void *, char **);
extern void set_str(char **, char **);
extern void set_int(int *, char **);
extern void set_flag(int *, char **);
extern void clear_flag(int *, char **);
extern void set_mode(char **, char **);
extern void set_dslip_mode(char **, char **);
extern void read_config_file(int *, char **);
extern void add_filter(void *var, char **);
extern int insert_packet(unsigned char *, int);
extern int lock(char *dev);
extern void unlock(void);
extern void fork_dialer(char *, int);
extern void flush_timeout_queue(void);
extern void set_up_tty(int, int, int);
extern void flush_prules(void);
extern void flush_filters(void);
extern void flush_vars(void);
extern void flush_strvars(void);
extern void parse_impulse(void *var, char **argv);
extern void parse_restrict(void *var, char **argv);
extern void parse_or_restrict(void *var, char **argv);
extern void parse_bringup(void *var, char **argv);
extern void parse_keepup(void *var, char **argv);
extern void parse_accept(void *var, char **argv);
extern void parse_ignore(void *var, char **argv);
extern void parse_wait(void *var, char **argv);
extern void parse_up(void *var, char **argv);
extern void parse_down(void *var, char **argv);
extern void parse_prule(void *var, char **argv);
extern void parse_var(void *var, char **argv);
extern void parse_set(void *var, char **argv);
extern void close_modem(void);
extern int open_modem (void);
extern void reopen_modem (void);
extern void finish_dial(void);
extern void ppp_start(void);
extern int ppp_set_addrs(void);
extern int ppp_dead(void);
extern int ppp_route_exists(void);
extern void ppp_stop(void);
extern void ppp_reroute(void);
extern void ppp_kill(void);
extern void ppp_zombie(void);
extern int ppp_rx_count(void);
extern void slip_start(void);
extern int slip_set_addrs(void);
extern int slip_dead(void);
extern void slip_stop(void);
extern void slip_reroute(void);
extern void slip_kill(void);
extern void slip_zombie(void);
extern int slip_rx_count(void);
extern void dev_start(void);
extern int dev_set_addrs(void);
extern int dev_dead(void);
extern void dev_stop(void);
extern void dev_reroute(void);
extern void dev_kill(void);
extern void dev_zombie(void);
extern int dev_rx_count(void);
extern void idle_filter_init(void);
extern void interface_up(void);
extern void interface_down(void);
extern void buffer_init(int *, char **);
extern int queue_empty(void);
extern int fw_wait(void);
extern int fw_reset_wait(void);
extern int next_alarm(void);
extern void buffer_packet(unsigned int,unsigned char *);
extern void forward_buffer(void);
extern void run_ip_up(void);
extern void run_ip_down(void);
extern void set_ptp(char *, int, char *, int);
extern void add_routes(char *, int, char *, char *, int);
extern void del_routes(char *, int, char *, char *, int);
extern void pipe_init(int, PIPE *);
extern int pipe_read(PIPE *);
extern void pipe_flush(PIPE *, int);
extern int set_proxyarp (unsigned int);
extern int clear_proxyarp (unsigned int);
extern int report_system_result(int,char *);
extern void mon_write(int,char *,int);
extern void background_system(const char *);
extern void block_timer();
extern void unblock_timer();
extern void del_impulse(FW_unit *unit);
extern void del_connection(FW_Connection *);
extern void slip_start_fail(unsigned long data);
