/* pppoatm.c - pppd plugin to implement PPPoATM protocol.
 *
 * Copyright 2000 Mitchell Blank Jr.
 * Based in part on work from Jens Axboe and Paul Mackerras.
 * Updated to ppp-2.4.1 by Bernhard Kaindl
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 */
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "pppd.h"
#include "pathnames.h"
#include "fsm.h" /* Needed for lcp.h to include cleanly */
#include "lcp.h"
#include <atm.h>
#include <linux/atmdev.h>
#include <linux/atmppp.h>
#include <sys/stat.h>
#include <net/if.h>
#include <sys/ioctl.h>

#ifndef EMBED
const char pppd_version[] = VERSION;
#else
extern char ppp_devnam[];
#endif

static struct sockaddr_atmpvc pvcaddr;
static char *qosstr = NULL;
//static int pppoatm_accept = 0;
static bool llc_encaps = 0;
static bool vc_encaps = 0;
static int device_got_set = 0;
static char *device_got_set_to = NULL;
static int pppoatm_max_mtu, pppoatm_max_mru;
static int setdevname_pppoatm(const char *cp);
#ifndef EMBED
struct channel pppoa_channel;
#endif

static option_t pppoa_options[] = {
	{ "device name", o_special, (void *) &setdevname_pppoatm,
	  "ATM service provider IDs: VPI.VCI",
	  OPT_PRIVFIX | OPT_NOARG  | OPT_STATIC,
	  devnam},
#if 0
	{ "accept", o_bool, &pppoatm_accept,
	  "set PPPoATM socket to accept incoming connections", 1 },
#endif
	{ "llc-encaps", o_bool, &llc_encaps,
	  "use LLC encapsulation for PPPoATM", 1},
	{ "vc-encaps", o_bool, &vc_encaps,
	  "use VC multiplexing for PPPoATM (default)", 1},
	{ "qos", o_string, &qosstr,
	  "set QoS for PPPoATM connection", 1},
	{ NULL }
};

/* returns:
 *  -1 if there's a problem with setting the device
 *   0 if we can't parse "cp" as a valid name of a device
 *   1 if "cp" is a reasonable thing to name a device
 * Note that we don't actually open the device at this point
 * We do need to fill in:
 *   devnam: a string representation of the device
 *   devstat: a stat structure of the device.  In this case
 *     we're not opening a device, so we just make sure
 *     to set up S_ISCHR(devstat.st_mode) != 1, so we
 *     don't get confused that we're on stdin.
 */
static int setdevname_pppoatm(const char *cp)
{
#ifdef EMBED
	int doit = 1;
#endif
	struct sockaddr_atmpvc addr;
	extern struct stat devstat;
syslog(0, "%s,%d - %s\n", __FILE__, __LINE__, cp);
	if (device_got_set) {
		if (device_got_set_to && strcmp(cp, device_got_set_to) == 0)
			return 1;
		return 0;
	}
	//info("PPPoATM setdevname_pppoatm: '%s'", cp);
	memset(&addr, 0, sizeof addr);
	if (text2atm(cp, (struct sockaddr *) &addr, sizeof(addr),
	    T2A_PVC | T2A_NAME) < 0) {
               if(doit)
                   info("atm does not recognize: %s", cp);
		return 0;
           }
	if (!doit) return 1;
	//if (!dev_set_ok()) return -1;
	memcpy(&pvcaddr, &addr, sizeof pvcaddr);
	strlcpy(devnam, cp, sizeof devnam);
	devstat.st_mode = S_IFSOCK;
#ifndef EMBED
	if (the_channel != &pppoa_channel) {
#else
	if (1) {
		static int once = 1;
		if (once) {
#endif
		static char *bad_options[] = {
			"noaccomp", "-ac",
			"default-asyncmap", "-am", "asyncmap", "-as", "escape",
			"receive-all",
			"crtscts", "-crtscts", "nocrtscts",
			"cdtrcts", "nocdtrcts",
			"xonxoff",
			"modem", "local", "sync",
			NULL };
			char **a;
#ifndef EMBED
		the_channel = &pppoa_channel;
#endif
		info("PPPoATM setdevname - remove unwanted options");
		for (a = bad_options; *a != NULL; a++)
			remove_option(*a);
		modem = 0;
		lcp_wantoptions[0].neg_accompression = 0;
		lcp_allowoptions[0].neg_accompression = 0;
		lcp_wantoptions[0].neg_asyncmap = 0;
		lcp_allowoptions[0].neg_asyncmap = 0;
		lcp_wantoptions[0].neg_pcompression = 0;
#ifdef EMBED
		}
		once = 0;
#endif
	}
	info("PPPoATM setdevname_pppoatm - SUCCESS:%s", cp);
	device_got_set = 1;
	device_got_set_to = strdup(cp);
	return 1;
}

#define pppoatm_overhead() (llc_encaps ? 6 : 2)

static void no_device_given_pppoatm(void)
{
	fatal("No vpi.vci specified");
}

static void set_line_discipline_pppoatm(int fd)
{
	struct atm_backend_ppp be;
	be.backend_num = ATM_BACKEND_PPP;
	if (!llc_encaps)
		be.encaps = PPPOATM_ENCAPS_VC;
	else if (!vc_encaps)
		be.encaps = PPPOATM_ENCAPS_LLC;
	else
		be.encaps = PPPOATM_ENCAPS_AUTODETECT;
	if (ioctl(fd, ATM_SETBACKEND, &be) < 0)
		fatal("ioctl(ATM_SETBACKEND): %m");
}

#if 0
static void reset_line_discipline_pppoatm(int fd)
{
	atm_backend_t be = ATM_BACKEND_RAW;
	/* 2.4 doesn't support this yet */
	(void) ioctl(fd, ATM_SETBACKEND, &be);
}
#endif

static int connect_pppoatm(void)
{
	int fd;
	struct atm_qos qos;

	system ("/sbin/modprobe pppoatm");

	if (!device_got_set)
		no_device_given_pppoatm();
	fd = socket(AF_ATMPVC, SOCK_DGRAM, 0);
	if (fd < 0)
		fatal("failed to create socket: %m");
	memset(&qos, 0, sizeof qos);
	qos.txtp.traffic_class = qos.rxtp.traffic_class = ATM_UBR;
	/* TODO: support simplified QoS setting */
	if (qosstr != NULL)
		if (text2qos(qosstr, &qos, 0))
			fatal("Can't parse QoS: \"%s\"");
	qos.txtp.max_sdu = lcp_allowoptions[0].mru + pppoatm_overhead();
	qos.rxtp.max_sdu = lcp_wantoptions[0].mru + pppoatm_overhead();
	qos.aal = ATM_AAL5;
	if (setsockopt(fd, SOL_ATM, SO_ATMQOS, &qos, sizeof(qos)) < 0)
		fatal("setsockopt(SO_ATMQOS): %m");
	/* TODO: accept on SVCs... */
	if (connect(fd, (struct sockaddr *) &pvcaddr,
	    sizeof(struct sockaddr_atmpvc)))
		fatal("connect(%s): %m", devnam);
	pppoatm_max_mtu = lcp_allowoptions[0].mru;
	pppoatm_max_mru = lcp_wantoptions[0].mru;
	set_line_discipline_pppoatm(fd);
	strcpy(ppp_devnam, devnam);
	return fd;
}

static void send_config_pppoa(int mtu,
			      u_int32_t asyncmap,
			      int pcomp,
			      int accomp)
{
	int sock;
	struct ifreq ifr;
	if (mtu > pppoatm_max_mtu)
		error("Couldn't increase MTU to %d", mtu);
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		fatal("Couldn't create IP socket: %m");
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_mtu = mtu;
	if (ioctl(sock, SIOCSIFMTU, (caddr_t) &ifr) < 0)
		fatal("ioctl(SIOCSIFMTU): %m");
	(void) close (sock);
}

static void recv_config_pppoa(int mru,
			      u_int32_t asyncmap,
			      int pcomp,
			      int accomp)
{
	if (mru > pppoatm_max_mru)
		error("Couldn't increase MRU to %d", mru);
}

#ifdef EMBED
void pppoa_plugin_init(void)
#else
void plugin_init(void)
#endif
{
#ifndef EMBED
#if defined(__linux__)
	extern int new_style_driver;	/* From sys-linux.c */
	if (!ppp_available() && !new_style_driver)
		fatal("Kernel doesn't support ppp_generic - "
		    "needed for PPPoATM");
#else
	fatal("No PPPoATM support on this OS");
#endif
#endif
	info("PPPoATM plugin_init");
	add_options(pppoa_options);

	tty_open_hook = connect_pppoatm;
	//tty_close_hook = disconnect_pppoe_ses;

	setdevname_hook = &setdevname_pppoatm;

	establish_ppp_hook = &generic_establish_ppp;
	disestablish_ppp_hook = &generic_disestablish_ppp;

	ppp_send_config_hook = &send_config_pppoa;
	ppp_recv_config_hook = &recv_config_pppoa;

    info("PPPoE Plugin Initialized");
}

#ifndef EMBED
struct channel pppoa_channel = {
    options: pppoa_options,
    process_extra_options: NULL,
    check_options: NULL,
    connect: &connect_pppoatm,
    disconnect: NULL,
    establish_ppp: &generic_establish_ppp,
    disestablish_ppp: &generic_disestablish_ppp,
    send_config: &send_config_pppoa,
    recv_config: &recv_config_pppoa,
    close: NULL,
    cleanup: NULL
};
#endif
