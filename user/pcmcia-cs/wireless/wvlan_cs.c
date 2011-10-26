/********************************************************************
 *	WaveLAN/IEEE PCMCIA Linux network device driver
 *
 *	by Andreas Neuhaus <andy@fasta.fh-dortmund.de>
 *	http://www.fasta.fh-dortmund.de/users/andy/wvlan/
 *
 *	This driver is free software; you can redistribute and/or
 *	modify it under the terms of the GNU General Public License;
 *	either version 2 of the license, or (at your option) any
 *	later version.
 *	Please send comments/bugfixes/patches to the above address.
 *
 *	Based on the Linux PCMCIA Programmer's Guide
 *	and Lucent Technologies' HCF-Light library (wvlan47).
 *
 *	See 'man 4 wvlan_cs' for more information.
 *
 * TODO
 *		We should use multiple Tx buffers to gain performance.
 *		Have a closer look to the endianess (PPC problems).
 *
 * HISTORY
 *	v1.0.7	11/01/2000 - Jean II and Anton Blanchard
 *		Dont hold spinlock during copy_{to,from}_user, we might
 *		sleep. (brought to my attention by Dave Gibson)
 *		New Ad-Hoc mode accepts ESSID=any (Jean II)
 *		Support new wireless extension - Transmit Power (Jean II)
 *              Added support for 3.3V cards, fixed IPv6 (David)
 *
 *	v1.0.6	7/12/2000 - David Hinds, Anton Blanchard, Jean II and others
 *		Endianess fix for PPC users, first try (David)
 *		Fix some ranges (power management, key size, ...) (me)
 *		Auto rate up to a maximum (for ex. up to 5.5) (me)
 *		Remove error on IW_ENCODE_RESTRICTED (me)
 *		Better error messages to catch stupid users (me)
 *		---
 *		Oups ! Firmware 6.06 *do* support port3 (me)
 *		Oups ! ibss mode is not fully functional in firmware 6.04 (me)
 *		Match Windows driver for selecting Ad-Hoc mode (me)
 *		Get MAC address earlier, so that if module parameters are
 *			invalid, we can still use wireless.opts... (me)
 *		Use ethX and not wvlanX by default (me)
 *		Minimal support for some PrismII cards (me)
 *		Check out of bound in getratelist (Paul Mackerras)
 *		Finish up the endianess fix for PPC and test it 
 *			(Paul Mackerras and Hugh Blemings)
 *		Check Cabletron Firmware 4.32 support (Anton)
 *
 *	v1.0.5	19/10/2000 - David Hinds, Jean II and others
 *		Support for 6.00 firmware (remove fragmentation - ? + me)
 *		Add Microwave Oven Robustness support (me)
 *		Fix a bug preventing RARP from working (?)
 *		---
 *		Fix SMP support (fix all those spinlocks - me)
 *		Add IBSS support, to enable 802.11 ad-hoc mode (Ross Finlayson)
 *		Integrate IBSS support with Wireless Extensions (me)
 *		Clean-up Wireless Extensions (#define and other stuff - me)
 *		Multi-card support for Wireless Extensions (me)
 *		Firmware madness support - Arghhhhh !!!!!! (me)
 *		---
 *		Proper firmware detection routines (me)
 *		Aggregate configuration change when closed (me)
 *		wireless.opts now works on old firmware (me)
 *		Integrate MWO robust to frag setting (me)
 *		copy_to/from in ioctl with irq on (me, requested by Alan)
 *		Add a few "static" and "inline" there and there (me)
 *		Update to new module init/cleanup procedures (me)
 *
 *	v1.0.4	2000/02/26
 *		Some changes to fit into kernel 2.3.x.
 *		Some changes to better fit into the new net API.
 *		Use of spinlocks for disabling interrupts.
 *		Conditional to allow ignoring tx timeouts.
 *		Disable interrupts during config/shutdown/reset.
 *		Credits go to Jean Tourrilhes for all the following:
 *		Promiscuous mode (tcpdump now work correctly).
 *		Set multicast Rx list (RTP now work correctly).
 *		Hook up watchdog timer in new net API.
 *		Update frag/rts to new W-Ext.
 *		Operating mode support + W-Ext (Neat...).
 *		Power Saving support + W-Ext (useless...).
 *		WEP (Privacy - Silver+Gold) support + W-Ext (yeah !!!).
 *		Disable interupts during reading wireless stats.
 *		(New quality indicator not included, need more work)
 *		Plus a few cleanups, comments and fixes...
 *
 *	v1.0.3	Skipped to not confuse with kernel 2.3.x driver
 *
 *	v1.0.2	2000/01/07
 *		Merged driver into the PCMCIA Card Services package
 *			(thanks to David Hinds).
 *		Removed README, added man page (man 4 wvlan_cs).
 *
 *	v1.0.1	1999/09/02
 *		Interrupts are now disabled during ioctl to prevent being
 *			disturbed during our fiddling with the NIC (occurred
 *			when using wireless tools while heavy loaded link).
 *		Fixed a problem with more than 6 spy addresses (thanks to
 *			Thomas Ekstrom).
 *		Hopefully fixed problems with bigger packet sizes than 1500.
 *		When you changed parameters that were specified at module
 *			load time later with wireless_tools and the card was
 *			reset afterward (e.g. by a Tx timeout), all changes
 *			were lost. Changes will stay now after a reset.
 *		Rewrote some parts of this README, added card LEDs description.
 *		Added medium_reservation, ap_density, frag_threshold and
 *			transmit_rate to module parameters.
 *		Applying the patch now also modifies the files SUPPORTED.CARDS
 *			and MAINTAINERS.
 *		Signal/noise levels are now reported in dBm (-102..-10).
 *		Added support for the new wireless extension (get wireless_
 *			tools 19). Credits go to Jean Tourrilhes for all
 *			the following:
 *		Setting channel by giving frequency value is now available.
 *		Setting/getting ESSID/BSSID/station-name is now possible
 *			via iwconfig.
 *		Support to set/get the desired/current bitrate.
 *		Support to set/get RTS threshold.
 *		Support to set/get fragmentation threshold.
 *		Support to set/get AP density.
 *		Support to set/get port type.
 *		Fixed a problem with ioctl calls when setting station/network
 *			name, where the new name string wasn't in kernel space
 *			(thanks to Danton Nunes).
 *		Driver sucessful tested on AlphaLinux (thanks to Peter Olson).
 *		Driver sucessful tested with WaveLAN Turbo cards.
 *
 *	v0.2.7	1999/07/20
 *		Changed release/detach code to fix hotswapping with 2.2/2.3
 *			kernels (thanks to Derrick J Brashear).
 *		Fixed wrong adjustment of receive buffer length. This was only
 *			a problem when a higher level protocol relies on correct
 *			length information, so it never occurred with IPv4
 *			(thanks to Henrik Gulbrandsen).
 *
 *	v0.2.6	1999/05/04
 *		Added wireless spy and histogram support. Signal levels
 *			are now reported in ad-hoc mode correctly, but you
 *			need to use iwspy for it, because we can 'hear' more
 *			than one remote host in ad-hoc mode (thanks
 *			to Albert K T Hui for the code and to Richard van
 *			Leeuwen for the technical details).
 *		Fixed a bug with wrong tx_bytes count.
 *		Added GPL file wvlan.COPYING.
 *
 *	v0.2.5	1999/03/12
 *		Hopefully fixed problems with the Makefile patch.
 *		Changed the interrupt service routine to do never lock up
 *			in an endless loop (if this ever would happen...).
 *		Missed a conditional which made the driver unable to compile
 *			on 2.0.x kernels (thanks to Glenn D. Golden).
 *
 *	v0.2.4	1999/03/10
 *		Tested in ad-hoc mode and with access point (many thanks
 *			to Frank Bruegmann, who made some hardware available
 *			to me so that I can now test it myself).
 *		Change the interrupt service routine to repeat on frame
 *			reception and deallocate the NICs receiving frame
 *			buffer correctly (thanks to Glenn D. Golden).
 *		Fixed a problem with checksums where under some circumstances
 *			an incorrect packet wasn't recognized. Switched
 *			on the kernel checksum checking (thanks to Glenn D. Golden).
 *		Setting the channel value is now checked against valid channel
 *			values which are read from the card.
 *		Added private ioctl (iwconfig priv) station_name, network_name
 *			and current_network. It needs an iwconfig capable of
 *			setting and gettings strings (thanks to Justin Seger).
 *		Ioctl (iwconfig) should now return the real current used channel.
 *		Setting the channel value is now only valid using ad-hoc mode.
 *			It's useless when using an access points.
 *		Renamed the ssid parameter to network_name and made it work
 *			correctly for all port_types. It should work now
 *			in ad-hoc networks as well as with access points.
 *		Added entries for the NCR WaveLAN/IEEE and the Cabletron
 *			RoamAbout 802.11 DS card (thanks to Richard van Leeuwen)
 *		Support to count the received and transmitted bytes
 *			if kernel version >2.1.25.
 *		Changed the reset method in case of Tx-timeouts.
 *		PM suspend/resume should work now (thanks to Dave Kristol).
 *		Changed installation and driver package. Read INSTALL in this
 *			file for information how it works now.
 *
 *	v0.2.3	1999/02/25
 *		Added support to set the own SSID
 *		Changed standard channel setting to 3 so that it works
 *			with Windows without specifying a channel (the
 *			Windows driver seem to default to channel 3).
 *		Fixed two problems with the Ethernet-II frame de/encapsulation.
 *
 *	v0.2.2	1999/02/07
 *		First public beta release.
 *		Added support to get link quality via iwconfig.
 *		Added support to change channel via iwconfig.
 *		Added changeable MTU setting (thanks to Tomasz Motylewski).
 *		Added Ethernet-II frame de/encapsulation, because
 *			HCF-Light doesn't support it.
 *
 *	v0.2.1	1999/02/03
 *		Added channel parameter.
 *		Rewrote the driver with information made public
 *			in Lucent's HCF-Light library. The HCF was
 *			slightly modified to get rid of the compiler
 *			warnings. The filenames were prefixed with
 *			wvlan_ to better fit into the pcmcia package.
 *
 *	v0.1d	1998/12/21
 *		Fixed a problem where the NIC was crashing during heavy
 *			loaded transmissions. Interrupts are now disabled
 *			during wvlan_tx() function. Seems to work fine now.
 *
 *	v0.1c	1998/12/20
 *		Driver works fine with ad-hoc network.
 *
 *	v0.1b	1998/12/19
 *		First successful send-tests.
 *
 *	v0.1a	1998/12/18
 *		First tests with card functions.
 */

#include <linux/config.h>
#include <linux/version.h>
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifdef __IN_PCMCIA_PACKAGE__
#include <pcmcia/config.h>
#include <pcmcia/k_compat.h>
#endif

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/malloc.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/system.h>
#include <asm/uaccess.h>

#include <pcmcia/version.h>
#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/cisreg.h>
#include <pcmcia/ds.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_arp.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>

#ifdef MODULE
#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#else
#define MOD_INC_USE_COUNT
#define MOD_DEC_USE_COUNT
#endif

#include <linux/wireless.h>
/* Note : v6 is included in : 2.0.37+ and 2.2.4+, adds ESSID */
/* Note : v8 is included in : 2.2.11+ and 2.3.14+, adds frag/rts/rate/nick */
/* Note : v9 is included in : 2.2.14+ and 2.3.25+, adds mode/ps/wep */
#if WIRELESS_EXT < 6
#warning "Wireless extension v8 or newer required - please upgrade your kernel"
#undef WIRELESS_EXT
#endif
#if WIRELESS_EXT < 9
#warning "Wireless extension v9 or newer prefered - please upgrade your kernel"
#endif
#define WIRELESS_SPY		// enable iwspy support
#undef HISTOGRAM		// disable histogram of signal levels

// This is needed for station_name, but we may not compile WIRELESS_EXT
#ifndef IW_ESSID_MAX_SIZE
#define IW_ESSID_MAX_SIZE	32
#endif /* IW_ESSID_MAX_SIZE */

#include "wvlan_hcf.h"

/* #define PCMCIA_DEBUG 1	// For developer only :-) */

// Undefine this if you want to ignore Tx timeouts
// (i.e. card will not be reset on Tx timeouts)
#define WVLAN_RESET_ON_TX_TIMEOUT


/********************************************************************
 * DEBUG
 */
#ifdef PCMCIA_DEBUG
static int pc_debug = PCMCIA_DEBUG;
MODULE_PARM(pc_debug, "i");
#define DEBUG(n, args...) if (pc_debug>=(n)) printk(KERN_DEBUG args);
#else
#define DEBUG(n, args...) {}
#endif
#define DEBUG_INFO		1
#define DEBUG_NOISY		2
#define DEBUG_TXRX		3
#define DEBUG_CALLTRACE		4
#define DEBUG_INTERRUPT		5

/********************************************************************
 * MISC
 */
static char *version = "1.0.6";
static dev_info_t dev_info = "wvlan_cs";
static dev_link_t *dev_list = NULL;

// Module parameters
static u_int irq_mask = 0xdeb8;				// Interrupt mask
static int irq_list[4] = { -1 };			// Interrupt list (alternative)
static int eth = 1;					// use ethX devname
static int mtu = 1500;
// Note : the following parameters can be also modified through Wireless
// Extension, and additional parameters are also available this way...
static int port_type = 1;				// Port-type [1]
static int allow_ibss = 0;				// Allow a IBSS [0]
static char network_name[IW_ESSID_MAX_SIZE+1] = "\0";	// Name of network []
static int channel = 3;					// Channel [3]
MODULE_PARM(irq_mask, "i");
MODULE_PARM(irq_list, "1-4i");
MODULE_PARM(eth, "i");
MODULE_PARM(mtu, "i");
MODULE_PARM(port_type, "i");
MODULE_PARM(allow_ibss, "i");
MODULE_PARM(network_name, "c" __MODULE_STRING(IW_ESSID_MAX_SIZE));
MODULE_PARM(channel, "i");
// Backward compatibility - This one is obsolete and will be removed soon
static char station_name[IW_ESSID_MAX_SIZE+1] = "\0";	// Name of station []
MODULE_PARM(station_name, "c" __MODULE_STRING(IW_ESSID_MAX_SIZE));

// Useful macros we have in pcmcia-cs but not in the kernel
#ifndef __IN_PCMCIA_PACKAGE__
#define DEV_KFREE_SKB(skb) dev_kfree_skb(skb);
#define skb_tx_check(dev, skb)
#define add_rx_bytes(stats, n) (stats)->rx_bytes += n;
#define add_tx_bytes(stats, n) (stats)->tx_bytes += n;
#endif

// Ethernet timeout is ((400*HZ)/1000), but we should use a higher
// value, because wireless transmissions are much slower
#define TX_TIMEOUT ((4000*HZ)/1000)

// Ethernet-II snap header
static char snap_header[] = { 0x00, 0x00, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };

// Valid MTU values (HCF_MAX_MSG (2304) is the max hardware frame size)
#define WVLAN_MIN_MTU 256
#define WVLAN_MAX_MTU (HCF_MAX_MSG - sizeof(snap_header))

// Max number of multicast addresses that the filter can accept
#define WVLAN_MAX_MULTICAST GROUP_ADDR_SIZE/6

// Frequency list (map channels to frequencies)
const long frequency_list[] = { 2412, 2417, 2422, 2427, 2432, 2437, 2442,
				2447, 2452, 2457, 2462, 2467, 2472, 2484 };

// Bit-rate list in 1/2 Mb/s (first is dummy - not for original turbo)
const int rate_list[] = { 0, 2, 4, -22, 11, 22, -4, -11, 0, 0, 0, 0 };

// A few details needed for WEP (Wireless Equivalent Privacy)
#define MAX_KEY_SIZE 13			// 128/104 (?) bits
#define MIN_KEY_SIZE  5			// 40 bits RC4 - WEP
#define MAX_KEYS      4			// 4 different keys

// Keep track of wvlanX devices
#define MAX_WVLAN_CARDS 16
static struct net_device *wvlandev_index[MAX_WVLAN_CARDS];

// Local data for netdevice
struct net_local {
	dev_node_t		node;
	struct net_device	*dev;		// backtrack device
	dev_link_t		*link;		// backtrack link
	spinlock_t		slock;		// spinlock
	int			interrupt;	// interrupt
	IFB_STRCT		ifb;		// WaveLAN HCF structure
	struct net_device_stats	stats;		// device stats
	u_char			promiscuous;	// Promiscuous mode
	u_char			allmulticast;	// All multicast mode
	int			mc_count;	// Number of multicast addrs
	int			need_commit;	// Need to set config
	/* Capabilities : what the firmware do support */
	int			has_port3;	// Ad-Hoc demo mode
	int			has_ibssid;	// IBSS Ad-Hoc mode
	int			has_mwo;	// MWO robust support
	int			has_wep;	// Lucent WEP support
	int			has_pwep;	// Prism WEP support
	int			has_pm;		// Power Management support
	/* Configuration : what is the current state of the hardware */
	int			port_type;	// Port-type [1]
	int			allow_ibss;	// Allow a IBSS [0]
	char	network_name[IW_ESSID_MAX_SIZE+1];	// Name of network []
	int			channel;	// Channel [3]
#ifdef WIRELESS_EXT
	char	station_name[IW_ESSID_MAX_SIZE+1];	// Name of station []
	int			ap_density;	// AP density [1]
	int	medium_reservation;		// RTS threshold [2347]
	int			frag_threshold;	// Frag. threshold [2346]
	int			mwo_robust;	// MWO robustness [0]
	int			transmit_rate;	// Transmit rate [3]
	int			wep_on;		// WEP enabled
	int			transmit_key;	// Key used for transmissions
	KEY_STRCT		key[MAX_KEYS];	// WEP keys & size
	int			pm_on;		// Power Management enabled
	int			pm_multi;	// Receive multicasts
	int			pm_period;	// Power Management period
#ifdef WIRELESS_SPY
	int			spy_number;
	u_char			spy_address[IW_MAX_SPY][MAC_ADDR_SIZE];
	struct iw_quality	spy_stat[IW_MAX_SPY];
#endif
#ifdef HISTOGRAM
	int			his_number;
	u_char			his_range[16];
	u_long			his_sum[16];
#endif
	struct iw_statistics	wstats;		// wireless stats
#endif /* WIRELESS_EXT */
};

// Shortcuts
#ifdef WIRELESS_EXT
typedef struct iw_statistics	iw_stats;
typedef struct iw_quality	iw_qual;
typedef struct iw_freq		iw_freq;
#endif /* WIRELESS_EXT */

// Show CardServices error message (syslog)
static void cs_error (client_handle_t handle, int func, int ret)
{
	error_info_t err = { func, ret };
	CardServices(ReportError, handle, &err);
}


/********************************************************************
 * FUNCTION PROTOTYPES
 */
static int wvlan_hw_setmaxdatalen (IFBP ifbp, int maxlen);
static int wvlan_hw_getmacaddr (IFBP ifbp, char *mac, int len);
static int wvlan_hw_getchannellist (IFBP ifbp);
static int wvlan_hw_setporttype (IFBP ifbp, int ptype);
static int wvlan_hw_getporttype (IFBP ifbp);
static int wvlan_hw_setallowibssflag (IFBP ifbp, int flag);
static int wvlan_hw_getallowibssflag (IFBP ifbp);
static int wvlan_hw_setstationname (IFBP ifbp, char *name);
static int wvlan_hw_getstationname (IFBP ifbp, char *name, int len);
static int wvlan_hw_setssid (IFBP ifbp, char *name, int ptype);
static int wvlan_hw_getssid (IFBP ifbp, char *name, int len, int cur, int ptype);
static int wvlan_hw_getbssid (IFBP ifbp, char *mac, int len);
static int wvlan_hw_setchannel (IFBP ifbp, int channel);
static int wvlan_hw_getchannel (IFBP ifbp);
static int wvlan_hw_getcurrentchannel (IFBP ifbp);
static int wvlan_hw_setthreshold (IFBP ifbp, int thrh, int cmd);
static int wvlan_hw_getthreshold (IFBP ifbp, int cmd);
static int wvlan_hw_setbitrate (IFBP ifbp, int brate);
static int wvlan_hw_getbitrate (IFBP ifbp, int cur);
static int wvlan_hw_getratelist (IFBP ifbp, char *brlist, int len);
#ifdef WIRELESS_EXT
static int wvlan_hw_getfrequencylist (IFBP ifbp, iw_freq *list, int max);
static int wvlan_getbitratelist (IFBP ifbp, __s32 *list, int max);
static int wvlan_hw_setpower (IFBP ifbp, int enabled, int cmd);
static int wvlan_hw_getpower (IFBP ifbp, int cmd);
static int wvlan_hw_setpmsleep (IFBP ifbp, int duration);
static int wvlan_hw_getpmsleep (IFBP ifbp);
static int wvlan_hw_getprivacy (IFBP ifbp);
static int wvlan_hw_setprivacy (IFBP ifbp, int mode, int transmit, KEY_STRCT *keys);
#endif /* WIRELESS_EXT */
static int wvlan_hw_setpromisc (IFBP ifbp, int promisc);
static int wvlan_hw_getfirmware (IFBP ifbp, int *first, int *major, int *minor);

static int wvlan_hw_config (struct net_device *dev);
static int wvlan_hw_shutdown (struct net_device *dev);
static int wvlan_hw_reset (struct net_device *dev);

struct net_device_stats *wvlan_get_stats (struct net_device *dev);
#ifdef WIRELESS_EXT
int wvlan_ioctl (struct net_device *dev, struct ifreq *rq, int cmd);
struct iw_statistics *wvlan_get_wireless_stats (struct net_device *dev);
#ifdef WIRELESS_SPY
static inline void wvlan_spy_gather (struct net_device *dev, u_char *mac, u_char *stats);
#endif
#ifdef HISTOGRAM
static inline void wvlan_his_gather (struct net_device *dev, u_char *stats);
#endif
#endif /* WIRELESS_EXT */
int wvlan_change_mtu (struct net_device *dev, int new_mtu);
static void wvlan_set_multicast_list (struct net_device *dev);

static void wvlan_watchdog (struct net_device *dev);
int wvlan_tx (struct sk_buff *skb, struct net_device *dev);
void wvlan_rx (struct net_device *dev, int len);

static int wvlan_open (struct net_device *dev);
static int wvlan_close (struct net_device *dev);

static void wvlan_interrupt (int irq, void *dev_id, struct pt_regs *regs);

static int wvlan_config (dev_link_t *link);
static void wvlan_release (u_long arg);

static dev_link_t *wvlan_attach (void);
static void wvlan_detach (dev_link_t *link);

static int wvlan_event (event_t event, int priority, event_callback_args_t *args);

extern int init_wvlan_cs (void);
extern void exit_wvlan_cs (void);


/********************** SPIN LOCK SUBROUTINES **********************/
/*
 * These 2 routines help to see what's happening with spinlock.
 * They are inline, so optimised away ;-)
 */

/*------------------------------------------------------------------*/
/*
 * Wrapper for disabling interrupts. Useful for debugging ;-)
 * (note : inline, so optimised away)
 */
static inline void
wv_driver_lock(struct net_local *	local,
	       unsigned long *		pflags)
{
  /* Disable interrupts and aquire the lock */
  spin_lock_irqsave(&local->slock, *pflags);
}

/*------------------------------------------------------------------*/
/*
 * Wrapper for re-enabling interrupts.
 */
static inline void
wv_driver_unlock(struct net_local *	local,
		 unsigned long *	pflags)
{
  /* Release the lock and reenable interrupts */
  spin_unlock_irqrestore(&local->slock, *pflags);
}

/********************************************************************
 * HARDWARE SETTINGS
 */
/* Note : most function below are called once in the code, so I added
 * the "inline" modifier. If a function is used more than once, please
 * remove the "inline"...
 * Jean II */
// Stupid constants helping clarity
#define WVLAN_CURRENT	1
#define WVLAN_DESIRED	0

static inline int wvlan_hw_setmaxdatalen (IFBP ifbp, int maxlen)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = CFG_CNF_MAX_DATA_LEN;
	ltv.id[0] = cpu_to_le16(maxlen);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CNF_MAX_DATA_LEN:0x%x) returned 0x%x\n", dev_info, maxlen, rc);
	return rc;
}

static inline int wvlan_hw_getmacaddr (IFBP ifbp, char *mac, int len)
{
	CFG_MAC_ADDR_STRCT ltv;
	int rc, l;

	ltv.len = 4;
	ltv.typ = CFG_CNF_OWN_MAC_ADDR;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CNF_OWN_MAC_ADDR) returned 0x%x\n", dev_info, rc);
	if (rc)
		return rc;
	l = min(len, ltv.len*2);
	memcpy(mac, (char *)ltv.mac_addr, l);
	return 0;
}

static int wvlan_hw_getchannellist (IFBP ifbp)
{
	CFG_ID_STRCT ltv;
	int rc, chlist;

	ltv.len = 2;
	ltv.typ = CFG_CHANNEL_LIST;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	chlist = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CHANNEL_LIST):0x%x returned 0x%x\n", dev_info, chlist, rc);
	return rc ? 0 : chlist;
}

static inline int wvlan_hw_setporttype (IFBP ifbp, int ptype)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = CFG_CNF_PORT_TYPE;
	ltv.id[0] = cpu_to_le16(ptype);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CNF_PORT_TYPE:0x%x) returned 0x%x\n", dev_info, ptype, rc);
	return rc;
}

static inline int wvlan_hw_getporttype (IFBP ifbp)
{
	CFG_ID_STRCT ltv;
	int rc, ptype;

	ltv.len = 2;
	ltv.typ = CFG_CNF_PORT_TYPE;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	ptype = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CNF_PORT_TYPE):0x%x returned 0x%x\n", dev_info, ptype, rc);
	return rc ? 0 : ptype;
}

static inline int wvlan_hw_setallowibssflag (IFBP ifbp, int flag)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = CFG_CREATE_IBSS;
	ltv.id[0] = cpu_to_le16(flag);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CREATE_IBSS:0x%x) returned 0x%x\n", dev_info, flag, rc);
	return rc;
}

static inline int wvlan_hw_getallowibssflag (IFBP ifbp)
{
	CFG_ID_STRCT ltv;
	int rc, flag;

	ltv.len = 2;
	ltv.typ = CFG_CREATE_IBSS;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	flag = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CREATE_IBSS):0x%x returned 0x%x\n", dev_info, flag, rc);
	return rc ? 0 : flag;
}

static inline int wvlan_hw_setstationname (IFBP ifbp, char *name)
{
	CFG_ID_STRCT ltv;
	int rc, l;

	ltv.len = 18;
	ltv.typ = CFG_CNF_OWN_NAME;
	l = min(strlen(name), ltv.len*2);
	ltv.id[0] = cpu_to_le16(l);
	memcpy((char *) &ltv.id[1], name, l);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CNF_OWN_NAME:'%s') returned 0x%x\n", dev_info, name, rc);
	return rc;
}

static inline int wvlan_hw_getstationname (IFBP ifbp, char *name, int len)
{
	CFG_ID_STRCT ltv;
	int rc, l;

	ltv.len = 18;
	ltv.typ = CFG_CNF_OWN_NAME;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CNF_OWN_NAME) returned 0x%x\n", dev_info, rc);
	if (rc)
		return rc;
	l = le16_to_cpup(&ltv.id[0]);
	if (l)
		l = min(len, l);
	else
		l = min(len, ltv.len*2);	/* It's a feature */
	memcpy(name, (char *) &ltv.id[1], l);
	name[l] = 0;
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CNF_OWN_NAME):'%s'\n", dev_info, name);
	return 0;
}

static inline int wvlan_hw_setssid (IFBP ifbp, char *name, int ptype)
{
	CFG_ID_STRCT ltv;
	int rc, l;

	ltv.len = 18;
	if (ptype == 3)
		ltv.typ = CFG_CNF_OWN_SSID;
	else
		ltv.typ = CFG_CNF_DESIRED_SSID;
	l = min(strlen(name), ltv.len*2);
	ltv.id[0] = cpu_to_le16(l);
	memcpy((char *) &ltv.id[1], name, l);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CNF_OWN/DESIRED_SSID:'%s') returned 0x%x\n", dev_info, name, rc);
	return rc;
}

static int wvlan_hw_getssid (IFBP ifbp, char *name, int len, int cur, int ptype)
{
	CFG_ID_STRCT ltv;
	int rc, l;

	ltv.len = 18;
	if (cur)
		ltv.typ = CFG_CURRENT_SSID;
	else
		if (ptype == 3)
			ltv.typ = CFG_CNF_OWN_SSID;
		else
			ltv.typ = CFG_CNF_DESIRED_SSID;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CNF_OWN/DESIRED/CURRENT_SSID) returned 0x%x\n", dev_info, rc);
	if (rc)
		return rc;
	l = le16_to_cpup(&ltv.id[0]);
	if (l)
	{
		l = min(len, l);
		memcpy(name, (char *) &ltv.id[1], l);
	}
	name[l] = '\0';
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CNF_OWN/DESIRED/CURRENT_SSID):'%s'\n", dev_info, name);
	return 0;
}

static inline int wvlan_hw_getbssid (IFBP ifbp, char *mac, int len)
{
	CFG_MAC_ADDR_STRCT ltv;
	int rc, l;

	ltv.len = 4;
	ltv.typ = CFG_CURRENT_BSSID;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CURRENT_BSSID) returned 0x%x\n", dev_info, rc);
	if (rc)
		return rc;
	l = min(len, ltv.len*2);
	memcpy(mac, (char *)ltv.mac_addr, l);
	return 0;
}

static inline int wvlan_hw_setchannel (IFBP ifbp, int channel)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = CFG_CNF_OWN_CHANNEL;
	ltv.id[0] = cpu_to_le16(channel);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CNF_OWN_CHANNEL:0x%x) returned 0x%x\n", dev_info, channel, rc);
	return rc;
}

/* Unused ??? */
static int wvlan_hw_getchannel (IFBP ifbp)
{
	CFG_ID_STRCT ltv;
	int rc, channel;

	ltv.len = 2;
	ltv.typ = CFG_CNF_OWN_CHANNEL;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	channel = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CNF_OWN_CHANNEL):0x%x returned 0x%x\n", dev_info, channel, rc);
	return rc ? 0 : channel;
}

static int wvlan_hw_getcurrentchannel (IFBP ifbp)
{
	CFG_ID_STRCT ltv;
	int rc, channel;

	ltv.len = 2;
	ltv.typ = CFG_CURRENT_CHANNEL;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	channel = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CURRENT_CHANNEL):0x%x returned 0x%x\n", dev_info, channel, rc);
	return rc ? 0 : channel;
}

static int wvlan_hw_setthreshold (IFBP ifbp, int thrh, int cmd)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = cmd;
	ltv.id[0] = cpu_to_le16(thrh);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(0x%x:0x%x) returned 0x%x\n", dev_info, cmd, thrh, rc);
	return rc;
}

static int wvlan_hw_getthreshold (IFBP ifbp, int cmd)
{
	CFG_ID_STRCT ltv;
	int rc, thrh;

	ltv.len = 2;
	ltv.typ = cmd;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	thrh = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(0x%x):0x%x returned 0x%x\n", dev_info, cmd, thrh, rc);
	return rc ? 0 : thrh;
}

/* Unused ? */
static int wvlan_hw_setbitrate (IFBP ifbp, int brate)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = CFG_TX_RATE_CONTROL;
	ltv.id[0] = cpu_to_le16(brate);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_TX_RATE_CONTROL:0x%x) returned 0x%x\n", dev_info, brate, rc);
	return rc;
}

static int wvlan_hw_getbitrate (IFBP ifbp, int cur)
{
	CFG_ID_STRCT ltv;
	int rc, brate;

	ltv.len = 2;
	ltv.typ = cur ? CFG_CURRENT_TX_RATE : CFG_TX_RATE_CONTROL;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	brate = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_TX_RATE_CONTROL):0x%x returned 0x%x\n", dev_info, brate, rc);
	return rc ? 0 : brate;
}

static int wvlan_hw_getratelist(IFBP ifbp, char *brlist, int brmaxlen)
{
	CFG_ID_STRCT ltv;
	int rc, brnum;

	ltv.len = 10;
	ltv.typ = CFG_SUPPORTED_DATA_RATES;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	brnum = le16_to_cpup(&ltv.id[0]);
	if (brnum > brmaxlen)
		brnum = brmaxlen;
	memcpy(brlist, (char *) &ltv.id[1], brnum);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_CHANNEL_LIST):0x%x returned 0x%x\n", dev_info, brnum, rc);
	return rc ? 0 : brnum;
}

#ifdef WIRELESS_EXT
static inline int wvlan_hw_getfrequencylist(IFBP ifbp, iw_freq *list, int max)
{
	int chlist = wvlan_hw_getchannellist(ifbp);
	int i, k = 0;

	/* Compute maximum number of freq to scan */
	if(max > 15)
		max = 15;

	/* Check availability */
	for(i = 0; i < max; i++)
		if((1 << i) & chlist)
		{
#if WIRELESS_EXT > 7
			list[k].i = i + 1;	/* Set the list index */
#endif /* WIRELESS_EXT */
			list[k].m = frequency_list[i] * 100000;
			list[k++].e = 1;	/* Values in table in MHz -> * 10^5 * 10 */
		}

	return k;
}

static inline int wvlan_getbitratelist(IFBP ifbp, __s32 *list, int max)
{
	char brlist[9];
	int brnum = wvlan_hw_getratelist(ifbp, brlist, sizeof(brlist));
	int i;

	/* Compute maximum number of freq to scan */
	if(brnum > max)
		brnum = max;

	/* Convert to Mb/s */
	for(i = 0; i < max; i++)
		list[i] = (brlist[i] & 0x7F) * 500000;

	return brnum;
}

static int wvlan_hw_setpower (IFBP ifbp, int enabled, int cmd)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = cmd;
	ltv.id[0] = cpu_to_le16(enabled);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(0x%x:0x%x) returned 0x%x\n", dev_info, cmd, enabled, rc);
	return rc;
}

static int wvlan_hw_getpower (IFBP ifbp, int cmd)
{
	CFG_ID_STRCT ltv;
	int rc, enabled;

	ltv.len = 2;
	ltv.typ = cmd;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	enabled = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(0x%x):0x%x returned 0x%x\n", dev_info, cmd, enabled, rc);
	return rc ? 0 : enabled;
}

static inline int wvlan_hw_setpmsleep (IFBP ifbp, int duration)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = CFG_CNF_MAX_SLEEP_DURATION;
	ltv.id[0] = cpu_to_le16(duration);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CNF_MAX_SLEEP_DURATION:0x%x) returned 0x%x\n", dev_info, duration, rc);
	return rc;
}

static inline int wvlan_hw_getpmsleep (IFBP ifbp)
{
	CFG_ID_STRCT ltv;
	int rc, duration;

	ltv.len = 2;
	ltv.typ = CFG_CNF_MAX_SLEEP_DURATION;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	duration = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CNF_MAX_SLEEP_DURATION):0x%x returned 0x%x\n", dev_info, duration, rc);
	return rc ? 0 : duration;
}

static int wvlan_hw_getprivacy (IFBP ifbp)
{
	CFG_ID_STRCT ltv;
	int rc, privacy;

	// This function allow to distiguish bronze cards from other
	// types, to know if WEP exist...
	// This is stupid, we have no way to distinguish the silver
	// and gold cards, because the call below return 1 in all
	// cases. Yuk...
	ltv.len = 2;
	ltv.typ = CFG_PRIVACY_OPTION_IMPLEMENTED;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	privacy = le16_to_cpup(&ltv.id[0]);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_PRIVACY_OPTION_IMPLEMENTED):0x%x returned 0x%x\n", dev_info, privacy, rc);
	return rc ? 0 : privacy;
}

static int wvlan_hw_setprivacy (IFBP ifbp, int mode, int transmit, KEY_STRCT *keys)
{
	CFG_ID_STRCT ltv;
	CFG_CNF_DEFAULT_KEYS_STRCT ltv_key;
	int rc;
	int i;

	if (mode)
	{
		// Set the index of the key used for transmission
		ltv.len = 2;
		ltv.typ = CFG_CNF_TX_KEY_ID;
		ltv.id[0] = cpu_to_le16(transmit);
		rc = hcf_put_info(ifbp, (LTVP) &ltv);
		DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CNF_TX_KEY_ID:0x%x) returned 0x%x\n", dev_info, mode, rc);
		if (rc)
			return rc;

		// Set the keys themselves (all in on go !)
		ltv_key.len = sizeof(KEY_STRCT)*MAX_KEYS/2 + 1;
		ltv_key.typ = CFG_CNF_DEFAULT_KEYS;
		memcpy((char *) &ltv_key.key, (char *) keys, sizeof(KEY_STRCT)*MAX_KEYS);
		for (i = 0; i < MAX_KEYS; ++i)
			cpu_to_le16s(&ltv_key.key[i].len);
		rc = hcf_put_info(ifbp, (LTVP) &ltv_key);
		DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CNF_TX_KEY_ID:0x%x) returned 0x%x\n", dev_info, mode, rc);
		if (rc)
			return rc;
	}
	// enable/disable encryption
	ltv.len = 2;
	ltv.typ = CFG_CNF_ENCRYPTION;
	ltv.id[0] = cpu_to_le16(mode);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_CNF_ENCRYPTION:0x%x) returned 0x%x\n", dev_info, mode, rc);
	return rc;
}
#endif /* WIRELESS_EXT */

static int wvlan_hw_setpromisc (IFBP ifbp, int promisc)
{
	CFG_ID_STRCT ltv;
	int rc;

	ltv.len = 2;
	ltv.typ = CFG_PROMISCUOUS_MODE;
	ltv.id[0] = cpu_to_le16(promisc);
	rc = hcf_put_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_PROMISCUOUS_MODE:0x%x) returned 0x%x\n", dev_info, promisc, rc);
	return rc;
}

static inline int wvlan_hw_getfirmware (IFBP ifbp, int *vendor, int *major, int *minor)
{
	CFG_ID_STRCT ltv;
	int	rc;

	ltv.len = 32;
	ltv.typ = CFG_STA_IDENTITY;
	rc = hcf_get_info(ifbp, (LTVP) &ltv);
	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_STA_IDENTITY) returned 0x%x\n", dev_info, rc);
	if (rc)
		return rc;

	/* Get the data we need (note : 16 bits operations) */
	*vendor = le16_to_cpup(&ltv.id[1]);
	*major = le16_to_cpup(&ltv.id[2]);
	*minor = le16_to_cpup(&ltv.id[3]);
	/* There is more data after that, but I can't guess its use */

	DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_STA_IDENTITY):%d-%d.%d\n", dev_info, *vendor, *major, *minor);

	return 0;
}


/********************************************************************
 * HARDWARE CONFIG / SHUTDOWN / RESET
 */

/*------------------------------------------------------------------*/
/*
 * Hardware configuration of the Wavelan
 * The caller *must* disable IRQs by himself before comming here.
 */
static int wvlan_hw_config (struct net_device *dev)
{
	struct net_local *local = (struct net_local *) dev->priv;
	int rc, i, chlist;
	int	vendor, major, minor;	/* Firmware revision */
	int	firmware;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_hw_config(%s)\n", dev->name);

	// Init the HCF library
	hcf_connect(&local->ifb, dev->base_addr);

	// Init hardware and turn on interrupts
	rc = hcf_action(&local->ifb, HCF_ACT_CARD_IN);
	DEBUG(DEBUG_NOISY, "%s: hcf_action(HCF_ACT_CARD_IN) returned 0x%x\n", dev_info, rc);
#if defined(PCMCIA_DEBUG) && (PCMCIA_DEBUG>=DEBUG_INTERRUPT)
	local->ifb.IFB_IntEnMask |= HREG_EV_TICK;
#endif
	rc = hcf_action(&local->ifb, HCF_ACT_INT_ON);
	DEBUG(DEBUG_NOISY, "%s: hcf_action(HCF_ACT_INT_ON) returned 0x%x\n", dev_info, rc);

 	/* Get MAC address (before we get a chance to fail) */
 	if (!rc) {
 		rc = wvlan_hw_getmacaddr(&local->ifb, dev->dev_addr, ETH_ALEN);
 		printk(KERN_INFO "%s: MAC address on %s is ", dev_info, dev->name);
 		for (i=0; i<ETH_ALEN; i++)
 			printk("%02x ", dev->dev_addr[i]);
 		printk("\n");
 	}
 
	/* Get firmware revision of the card */
	if (!rc)
 		rc = wvlan_hw_getfirmware(&local->ifb, &vendor, &major, &minor);

	/* Process firmware info to know what it supports */
	firmware = (major << 16) + minor;
 	if(!rc) {
 		switch(vendor) {
 		case 0x1:
 			/* This is a Lucent card : Wavelan IEEE, Orinoco,
 			 * Cabletron/Enterasys Roamabout or ELSA cards.
 			 * This is what we mainly support...
 			 * Note : this will work at least for Lucent
 			 * firmwares */
 			local->has_port3  = 1;
 			local->has_ibssid = ((firmware >= 0x60006) +
					     (firmware >= 0x60010));
 			local->has_mwo    = (firmware >= 0x60000);
 			local->has_wep    = (firmware >= 0x40020);
 			local->has_pwep   = 0;
 			local->has_pm     = (firmware >= 0x40020);
 			/* Note : I've tested the following firmwares :
 			 * 1.16 ; 4.08 ; 4.52 ; 6.04 ; 6.06 and 6.16
 			 * Jean II */
			/* Tested CableTron 4.32 - Anton */
 			break;
		case 0x2:
 		case 0x6:
 			/* This is a PrismII card. It is is *very* similar
 			 * to the Lucent, and the driver work 95%,
 			 * therefore, we attempt to support it... */
 			printk(KERN_NOTICE "%s: This is a PrismII card, not a Wavelan IEEE card :-(
You may want report firmare revision (0x%X) and what the card support.
I will try to make it work, but you should look for a better driver.\n", dev_info, firmware);
 			local->has_port3  = 1;
 			local->has_ibssid = 0;
 			local->has_mwo    = 0;
 			local->has_wep    = 0;
 			local->has_pwep   = 1;
 			local->has_pm     = 1;
 			/* Would need to reverse engineer encryption support,
 			 * somebody with a card should do that... */
 			/* Transmit rate also seem to be different. */
 			/* Note : currently untested... Jean II */
 			break;
 		default:
 			printk(KERN_NOTICE "%s: Unrecognised card, card return vendor = 0x%04X, please report...\n", dev_info, vendor);
 			break;
 		}
  	}
 
 	printk(KERN_INFO "%s: Found firmware 0x%X (vendor %d) - Firmware capabilities : %d-%d-%d-%d-%d\n",
 	      dev_info, firmware, vendor, local->has_port3, local->has_ibssid,
	      local->has_mwo, local->has_wep, local->has_pm);

 	if(!rc) {
 		/* Check for a few user mistakes... Cut down on support ;-) */
 		if((!local->has_port3) && (local->port_type == 3)) {
 			printk(KERN_NOTICE "%s: This firmware doesn't support ``port_type=3'', please use iwconfig.\n", dev_info);
 			rc = 255;
 		}
 		if((!local->has_ibssid) && (local->allow_ibss)) {
 			printk(KERN_NOTICE "%s: This firmware doesn't support ``allow_ibss=1'', please update it.\n", dev_info);
 			rc = 255;
 		}
 		if((local->allow_ibss) && (local->has_ibssid == 1) &&
		   (local->network_name[0] == '\0')) {
 			printk(KERN_NOTICE "%s: This firmware require an ESSID in Ad-Hoc mode, please use iwconfig.\n", dev_info);
 			rc = 255;
 		}
 		if((local->has_ibssid) && (local->port_type == 3)) {
 			printk(KERN_NOTICE "%s: Warning, you are using the old proprietary Ad-Hoc mode (not the IBSS Ad-Hoc mode).\n", dev_info);
 		}
	}

	// Set hardware parameters
	if (!rc)
		rc = wvlan_hw_setmaxdatalen(&local->ifb, HCF_MAX_MSG);
	if (!rc)
		rc = wvlan_hw_setporttype(&local->ifb, local->port_type);
	if (!rc && *(local->network_name))
		rc = wvlan_hw_setssid(&local->ifb, local->network_name,
				      local->port_type);
	/* Firmware 4.08 doesn't like that at all :-( */
	if (!rc && (local->has_ibssid))
		rc = wvlan_hw_setallowibssflag(&local->ifb, local->allow_ibss);

#ifdef WIRELESS_EXT
	// Set other hardware parameters
	if (!rc && *(local->station_name))
		rc = wvlan_hw_setstationname(&local->ifb, local->station_name);
	if (!rc)
		rc = wvlan_hw_setthreshold(&local->ifb, local->ap_density, CFG_CNF_SYSTEM_SCALE);
	if (!rc)
		rc = wvlan_hw_setthreshold(&local->ifb, local->transmit_rate, CFG_TX_RATE_CONTROL);
	if (!rc)
		rc = wvlan_hw_setthreshold(&local->ifb, local->medium_reservation, CFG_RTS_THRH);
	/* Normal fragmentation for v4 and earlier */
	if (!rc && (!local->has_mwo))
		rc = wvlan_hw_setthreshold(&local->ifb, local->frag_threshold, CFG_FRAGMENTATION_THRH);
	/* MWO robustness for v6 and later */
	if (!rc && (local->has_mwo))
		rc = wvlan_hw_setthreshold(&local->ifb, local->mwo_robust, CFG_CNF_MICRO_WAVE);
	/* Firmware 4.08 doesn't like those at all :-( */
	if (!rc && (local->has_wep))
		rc = wvlan_hw_setprivacy(&local->ifb, local->wep_on, local->transmit_key, local->key);
	if (!rc && (local->has_pm))
		rc = wvlan_hw_setpower(&local->ifb, local->pm_on, CFG_CNF_PM_ENABLED);
	if (!rc && (local->has_pm) && (local->pm_on))
		rc = wvlan_hw_setpower(&local->ifb, local->pm_multi, CFG_CNF_MCAST_RX);
	if (!rc && (local->has_pm) && (local->pm_on))
		rc = wvlan_hw_setpmsleep(&local->ifb, local->pm_period);
#endif /* WIRELESS_EXT */

	// Check valid channel settings
	if (!rc && ((local->port_type == 3) || (local->allow_ibss))) {
		chlist = wvlan_hw_getchannellist(&local->ifb);
		printk(KERN_INFO "%s: Valid channels: ", dev_info);
		for (i=1; i<17; i++)
			if (1<<(i-1) & chlist)
				printk("%d ", i);
		printk("\n");
		if (local->channel < 1 || local->channel > 16
		    || !(1 << (local->channel - 1) & chlist))
			printk(KERN_WARNING "%s: Channel value of %d is invalid!\n", dev_info, local->channel);
		else
			rc = wvlan_hw_setchannel(&local->ifb, local->channel);
	}

	// Enable hardware
	if (!rc)
	{
		rc = hcf_enable(&local->ifb, 0);
		DEBUG(DEBUG_NOISY, "%s: hcf_enable(0) returned 0x%x\n", dev_info, rc);
	}

	// Report error if any
	if (rc)
		printk(KERN_WARNING "%s: Initialization failed!\n", dev_info);

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_hw_config()\n");
	return rc;
}

/*------------------------------------------------------------------*/
/*
 * Wrapper for calling wvlan_hw_config() with irq disabled
 */
static inline int wvlan_hw_config_locked (struct net_device *dev)
{
	struct net_local *local = (struct net_local *) dev->priv;
	unsigned long flags;
	int ret;

	wv_driver_lock(local, &flags);
	ret = wvlan_hw_config(dev);
	wv_driver_unlock(local, &flags);

	return ret;
}

/*------------------------------------------------------------------*/
/*
 * Hardware de-configuration of the Wavelan (switch off the device)
 * The caller *must* disable IRQs by himself before comming here.
 */
static int wvlan_hw_shutdown (struct net_device *dev)
{
	struct net_local *local = (struct net_local *) dev->priv;
	int rc;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_hw_shutdown(%s)\n", dev->name);

	// Disable and shutdown hardware
	rc = hcf_disable(&local->ifb, 0);
	DEBUG(DEBUG_NOISY, "%s: hcf_disable(0) returned 0x%x\n", dev_info, rc);
	rc = hcf_action(&local->ifb, HCF_ACT_INT_OFF);
	DEBUG(DEBUG_NOISY, "%s: hcf_action(HCF_ACT_INT_OFF) returned 0x%x\n", dev_info, rc);
	rc = hcf_action(&local->ifb, HCF_ACT_CARD_OUT);
	DEBUG(DEBUG_NOISY, "%s: hcf_action(HCF_ACT_CARD_OUT) returned 0x%x\n", dev_info, rc);

	// Release HCF library
	hcf_disconnect(&local->ifb);

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_hw_shutdown()\n");
	return 0;
}

/*------------------------------------------------------------------*/
/*
 * "light" hardware reset of the Wavelan
 * The caller *must* disable IRQs by himself before comming here.
 */
static int wvlan_hw_reset (struct net_device *dev)
{
	struct net_local *local = (struct net_local *) dev->priv;
	int rc;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_hw_reset(%s)\n", dev->name);

	// Disable hardware
	rc = hcf_disable(&local->ifb, 0);
	DEBUG(DEBUG_NOISY, "%s: hcf_disable(0) returned 0x%x\n", dev_info, rc);
	rc = hcf_action(&local->ifb, HCF_ACT_INT_OFF);
	DEBUG(DEBUG_NOISY, "%s: hcf_action(HCF_ACT_INT_OFF) returned 0x%x\n", dev_info, rc);

	// Re-Enable hardware
	rc = hcf_action(&local->ifb, HCF_ACT_INT_ON);
	DEBUG(DEBUG_NOISY, "%s: hcf_action(HCF_ACT_INT_ON) returned 0x%x\n", dev_info, rc);
	rc = hcf_enable(&local->ifb, 0);
	DEBUG(DEBUG_NOISY, "%s: hcf_enable(0) returned 0x%x\n", dev_info, rc);

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_hw_reset()\n");
	return rc;
}


/********************************************************************
 * NET STATS / IOCTL
 */
struct net_device_stats *wvlan_get_stats (struct net_device *dev)
{
	DEBUG(DEBUG_CALLTRACE, "<> wvlan_get_stats(%s)\n", dev->name);
	return(&((struct net_local *) dev->priv)->stats);
}

#ifdef WIRELESS_EXT
int wvlan_ioctl (struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct net_local *local = (struct net_local *) dev->priv;
	struct iwreq *wrq = (struct iwreq *) rq;
	unsigned long flags;
	int rc = 0;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_ioctl(%s, cmd=0x%x)\n", dev->name, cmd);

	// Disable interrupts
	wv_driver_lock(local, &flags);

	switch (cmd)
	{
		// Get name
		case SIOCGIWNAME:
			strcpy(wrq->u.name, "IEEE 802.11-DS");
			break;

		// Set frequency/channel
		case SIOCSIWFREQ:
			// If setting by frequency, convert to a channel
			if((wrq->u.freq.e == 1) &&
			   (wrq->u.freq.m >= (int) 2.412e8) &&
			   (wrq->u.freq.m <= (int) 2.487e8))
			{
				int f = wrq->u.freq.m / 100000;
				int c = 0;
				while((c < 14) && (f != frequency_list[c]))
					c++;
				// Hack to fall through...
				wrq->u.freq.e = 0;
				wrq->u.freq.m = c + 1;
			}
			// Setting by channel number
			if (((local->port_type != 3) && (!local->allow_ibss))
			    || (wrq->u.freq.m > 1000) || (wrq->u.freq.e > 0))
				rc = -EOPNOTSUPP;
			else
			{
				int channel = wrq->u.freq.m;
				int chlist = wvlan_hw_getchannellist(&local->ifb);
				if (channel<1 || channel>16 || !(1<<(channel-1) & chlist))
				{
					DEBUG(DEBUG_INFO, "%s: New channel value of %d for %s is invalid!\n", dev_info, wrq->u.freq.m, dev->name);
					rc = -EINVAL;
				}
				else
				{
					local->channel = wrq->u.freq.m;
					local->need_commit = 1;
				}
			}
			break;

		// Get frequency/channel
		case SIOCGIWFREQ:
#ifdef WEXT_USECHANNELS
			wrq->u.freq.m = wvlan_hw_getcurrentchannel(&local->ifb);
			wrq->u.freq.e = 0;
#else
			{
				int f = wvlan_hw_getcurrentchannel(&local->ifb);
				wrq->u.freq.m = frequency_list[f-1] * 100000;
				wrq->u.freq.e = 1;
			}
#endif
			break;

		// Set desired network name (ESSID)
		case SIOCSIWESSID:
			if (wrq->u.data.pointer)
			{
				char	essid[IW_ESSID_MAX_SIZE + 1];

				/* Check if we asked for `any' */
				if(wrq->u.data.flags == 0)
				{
					essid[0] = '\0';
				}
				else
				{
					/* Check the size of the string */
					if(wrq->u.data.length >
					   IW_ESSID_MAX_SIZE + 1)
					{
						rc = -E2BIG;
						break;
					}
					wv_driver_unlock(local, &flags);
					rc = copy_from_user(essid,
						       wrq->u.data.pointer,
						       wrq->u.data.length);
					wv_driver_lock(local, &flags);
					if (rc) {
						rc = -EFAULT;
						break;
					}
					essid[IW_ESSID_MAX_SIZE] = '\0';
				}
				strncpy(local->network_name, essid, sizeof(local->network_name)-1);
				local->need_commit = 1;
			}
			break;

		// Get current network name (ESSID)
		case SIOCGIWESSID:
			if (wrq->u.data.pointer)
			{
				char essid[IW_ESSID_MAX_SIZE + 1];
				/* Get the essid that was set */
				wvlan_hw_getssid(&local->ifb, essid,
						 IW_ESSID_MAX_SIZE,
						 WVLAN_DESIRED,
						 local->port_type);
				/* If it was set to any, get the current one */
				if(strlen(essid) == 0)
					wvlan_hw_getssid(&local->ifb, essid,
							 IW_ESSID_MAX_SIZE,
							 WVLAN_CURRENT,
							 local->port_type);

				/* Push it out ! */
				wrq->u.data.length = strlen(essid) + 1;
				wrq->u.data.flags = 1; /* active */
				wv_driver_unlock(local, &flags);
				rc = copy_to_user(wrq->u.data.pointer, essid, sizeof(essid));
				wv_driver_lock(local, &flags);
				if (rc)
					rc = -EFAULT;
			}
			break;

		// Get current Access Point (BSSID)
		case SIOCGIWAP:
			wvlan_hw_getbssid(&local->ifb, wrq->u.ap_addr.sa_data, ETH_ALEN);
			wrq->u.ap_addr.sa_family = ARPHRD_ETHER;
			break;

#if WIRELESS_EXT > 7
		// Set desired station name
		case SIOCSIWNICKN:
			if (wrq->u.data.pointer)
			{
				char	name[IW_ESSID_MAX_SIZE + 1];

				/* Check the size of the string */
				if(wrq->u.data.length > IW_ESSID_MAX_SIZE + 1)
				{
					rc = -E2BIG;
					break;
				}
				wv_driver_unlock(local, &flags);
				rc = copy_from_user(name, wrq->u.data.pointer, wrq->u.data.length);
				wv_driver_lock(local, &flags);
				if (rc) {
					rc = -EFAULT;
					break;
				}
				name[IW_ESSID_MAX_SIZE] = '\0';
				strncpy(local->station_name, name, sizeof(local->station_name)-1);
				local->need_commit = 1;
			}
			break;

		// Get current station name
		case SIOCGIWNICKN:
			if (wrq->u.data.pointer)
			{
				char name[IW_ESSID_MAX_SIZE + 1];
				wvlan_hw_getstationname(&local->ifb, name, IW_ESSID_MAX_SIZE);
				wrq->u.data.length = strlen(name) + 1;
				wv_driver_unlock(local, &flags);
				rc = copy_to_user(wrq->u.data.pointer, name, sizeof(name));
				wv_driver_lock(local, &flags);
				if (rc)
					rc = -EFAULT;
			}
			break;

		// Set the desired bit-rate
		case SIOCSIWRATE:
		{
			// Start the magic...
			char	brlist[9];
			int	brnum = wvlan_hw_getratelist(&local->ifb, brlist, sizeof(brlist));
			int	brate = wrq->u.bitrate.value/500000;
			int	wvrate = 0;

			// Auto or fixed ?
			if(wrq->u.bitrate.fixed == 0) {
				// Is there a valid value ?
				if(wrq->u.bitrate.value == -1)
					wvrate = 3;
				else {
					// Setting by rate value
					// Find index in magic table
					while((rate_list[wvrate] != -brate) &&
					      (wvrate < (brnum * 2)))
						wvrate++;
				}
			} else
				if((wrq->u.bitrate.value <= (brnum * 2 - 1)) &&
				   (wrq->u.bitrate.value > 0))
				{
					// Setting by rate index
					wvrate = wrq->u.bitrate.value;
				} else {
					// Setting by rate value
					// Find index in magic table
					while((rate_list[wvrate] != brate) &&
					      (wvrate < (brnum * 2)))
						wvrate++;
				}

			// Check if in range
			if((wvrate < 1) || (wvrate >= (brnum * 2)))
			{
				rc = -EINVAL;
				break;
			}
			local->transmit_rate = wvrate;
			local->need_commit = 1;
			break;
		}

		// Get the current bit-rate
		case SIOCGIWRATE:
			{
				int	wvrate = wvlan_hw_getbitrate(&local->ifb, WVLAN_DESIRED);
				int	brate = rate_list[wvrate];

				// Auto ?
				if (brate < 0)
				{
					wrq->u.bitrate.fixed = 0;
					wvrate = wvlan_hw_getbitrate(&local->ifb, WVLAN_CURRENT);
					brate = 2 * wvrate;
					// Mandatory kludge!
					if (wvrate == 6)
						brate = 11;
				}
				else
					wrq->u.bitrate.fixed = 1;

				wrq->u.bitrate.value = brate * 500000;
#if WIRELESS_EXT > 8
				wrq->u.bitrate.disabled = 0;
#endif
			}
			break;

		// Set the desired AP density
		case SIOCSIWSENS:
			{
				int dens = wrq->u.sens.value;
				if((dens < 1) || (dens > 3))
				{
					rc = -EINVAL;
					break;
				}
				local->ap_density = dens;
				local->need_commit = 1;
			}
			break;

		// Get the current AP density
		case SIOCGIWSENS:
			wrq->u.sens.value = wvlan_hw_getthreshold(&local->ifb, CFG_CNF_SYSTEM_SCALE);
			wrq->u.sens.fixed = 0;	/* auto */
			break;
#endif /* WIRELESS_EXT > 7 */

#if WIRELESS_EXT > 8
		// Set the desired RTS threshold
		case SIOCSIWRTS:
			{
				int rthr = wrq->u.rts.value;
				// if(wrq->u.rts.fixed == 0) we should complain
				if(wrq->u.rts.disabled)
					rthr = 2347;
				if((rthr < 0) || (rthr > 2347))
				{
					rc = -EINVAL;
					break;
				}
				local->medium_reservation = rthr;
				local->need_commit = 1;
			}
			break;

		// Get the current RTS threshold
		case SIOCGIWRTS:
			wrq->u.rts.value = wvlan_hw_getthreshold(&local->ifb, CFG_RTS_THRH);
			wrq->u.rts.disabled = (wrq->u.rts.value == 2347);
			wrq->u.rts.fixed = 1;
			break;

		// Set the desired fragmentation threshold
		case SIOCSIWFRAG:
			/* Check if firmware v4 or v6 */
			if(local->has_mwo) {
				int fthr = wrq->u.frag.value;
				/* v6 : fragmentation is now controlled by
				 * MWO robust setting */
				// if(wrq->u.frag.fixed == 1) should complain
				if(wrq->u.frag.disabled)
					fthr = 0;
				if((fthr < 0) || (fthr > 2347)) {
					rc = -EINVAL;
				} else {
					local->mwo_robust = (fthr > 0);
					local->need_commit = 1;
				}
			} else {
				int fthr = wrq->u.frag.value;
				/* v4 : we can set frag threshold */
				// if(wrq->u.frag.fixed == 0) should complain
				if(wrq->u.frag.disabled)
					fthr = 2346;
				if((fthr < 256) || (fthr > 2346)) {
					rc = -EINVAL;
				} else {
					fthr &= ~0x1;	// Get an even value
					local->frag_threshold = fthr;
					local->need_commit = 1;
				}
			}
			break;

		// Get the current fragmentation threshold
		case SIOCGIWFRAG:
			/* Check if firmware v4 or v6 */
			if(local->has_mwo) {
				if(wvlan_hw_getthreshold(&local->ifb, CFG_CNF_MICRO_WAVE))
					wrq->u.frag.value = 2347;
				else
					wrq->u.frag.value = 0;
				wrq->u.frag.disabled = !(wrq->u.frag.value);
				wrq->u.frag.fixed = 0;
			} else {
				wrq->u.frag.value = wvlan_hw_getthreshold(&local->ifb, CFG_FRAGMENTATION_THRH);
				wrq->u.frag.disabled = (wrq->u.frag.value >= 2346);
				wrq->u.frag.fixed = 1;
			}
			break;

		// Set port type
		case SIOCSIWMODE:
			/* Big firmware trouble here !
			 * In v4 and v6.04, the ad-hoc mode supported is the
			 * Lucent proprietary Ad-Hoc demo mode.
			 * Starting with v6.06, the ad-hoc mode supported is
			 * the standard 802.11 IBSS Ad-Hoc mode.
			 * Jean II
			 */
			if(local->has_ibssid) {
				/* v6 : set the IBSS flag */
				char ibss = 0;

				/* Paranoia */
				if(local->port_type != 1)
					local->port_type = 1;

				switch (wrq->u.mode)
				{
					case IW_MODE_ADHOC:
						ibss = 1;
						// Fall through
					case IW_MODE_INFRA:
						local->allow_ibss = ibss;
						local->need_commit = 1;
						break;
					default:
						rc = -EINVAL;
				}
			} else {
				/* v4 : set the correct port type */
				char ptype = 1;

				/* Note : this now works properly with
				 * all firmware ;-) */

				/* Paranoia */
				if(local->allow_ibss)
					local->allow_ibss = 0;

				switch (wrq->u.mode)
				{
					case IW_MODE_ADHOC:
						ptype = 3;
						// Fall through
					case IW_MODE_INFRA:
						local->port_type = ptype;
						local->need_commit = 1;
						break;
					default:
						rc = -EINVAL;
				}
			}
			break;

		// Get port type
		case SIOCGIWMODE:
			/* Check for proprietary Ad-Hoc demo mode */
			if (wvlan_hw_getporttype(&local->ifb) == 1)
				wrq->u.mode = IW_MODE_INFRA;
			else
				wrq->u.mode = IW_MODE_ADHOC;
			/* Check for compliant 802.11 IBSS Ad-Hoc mode */
			if ((local->has_ibssid) &&
			    (wvlan_hw_getallowibssflag(&local->ifb) == 1))
				wrq->u.mode = IW_MODE_ADHOC;
			break;

		// Set the desired Power Management mode
		case SIOCSIWPOWER:
			// Disable it ?
			if(wrq->u.power.disabled) {
				local->pm_on = 0;
				local->need_commit = 1;
			} else {
				// Check mode
				switch(wrq->u.power.flags & IW_POWER_MODE)
				{
					case IW_POWER_UNICAST_R:
						local->pm_multi = 0;
						local->need_commit = 1;
						break;
					case IW_POWER_ALL_R:
						local->pm_multi = 1;
						local->need_commit = 1;
						break;
					case IW_POWER_ON:	// None = ok
						break;
					default:	// Invalid
						rc = -EINVAL;
				}
				// Set period
				if (wrq->u.power.flags & IW_POWER_PERIOD)
				{
					// Activate PM
					local->pm_on = 1;
					// Hum: check max/min values ?
					local->pm_period = wrq->u.power.value/1000;
					local->need_commit = 1;
				}
				if (wrq->u.power.flags & IW_POWER_TIMEOUT)
					rc = -EINVAL;	// Invalid
			}
			break;

		// Get the power management settings
		case SIOCGIWPOWER:
			wrq->u.power.disabled = !wvlan_hw_getpower(&local->ifb, CFG_CNF_PM_ENABLED);
			wrq->u.power.flags = IW_POWER_PERIOD;
			wrq->u.power.value = wvlan_hw_getpmsleep (&local->ifb) * 1000;
			if (wvlan_hw_getpower(&local->ifb, CFG_CNF_MCAST_RX))
				wrq->u.power.flags |= IW_POWER_ALL_R;
			else
				wrq->u.power.flags |= IW_POWER_UNICAST_R;
			break;

		// Set WEP keys and mode
		case SIOCSIWENCODE:
			// Is it supported?
			if (!wvlan_hw_getprivacy(&local->ifb))
			{
				rc = -EOPNOTSUPP;
				break;
			}
			// Basic checking: do we have a key to set?
			if (wrq->u.encoding.pointer != (caddr_t) 0)
			{
				int index = (wrq->u.encoding.flags & IW_ENCODE_INDEX) - 1;
				// Check the size of the key
				if (wrq->u.encoding.length > MAX_KEY_SIZE)
				{
					rc = -EINVAL;
					break;
				}
				// Check the index
				if ((index < 0) || (index >= MAX_KEYS))
					index = local->transmit_key;
				// Cleanup
				memset(local->key[index].key, 0, MAX_KEY_SIZE);
				// Copy the key in the driver
				wv_driver_unlock(local, &flags);
				rc = copy_from_user(local->key[index].key, wrq->u.encoding.pointer, wrq->u.encoding.length);
				wv_driver_lock(local, &flags);
				if (rc) {
					rc = -EFAULT;
					local->key[index].len = 0;
					break;
				}
				// Set the length
				if (wrq->u.encoding.length > MIN_KEY_SIZE)
					local->key[index].len = MAX_KEY_SIZE;
				else
					if (wrq->u.encoding.length > 0)
						local->key[index].len = MIN_KEY_SIZE;
					else
						local->key[index].len = 0;
				// Enable WEP (if possible)
				if ((index == local->transmit_key) && (local->key[local->transmit_key].len > 0))
					local->wep_on = 1;
			}
			else
			{
				int index = (wrq->u.encoding.flags & IW_ENCODE_INDEX) - 1;
				// Do we want to just set the current transmit key?
				if ((index >= 0) && (index < MAX_KEYS))
				{
					if (local->key[index].len > 0)
					{
						local->transmit_key = index;
						local->wep_on = 1;
					}
					else
						rc = -EINVAL;
				}
			}
			// Read the flags
			if (wrq->u.encoding.flags & IW_ENCODE_DISABLED)
				local->wep_on = 0;	// disable encryption
			if (wrq->u.encoding.flags & IW_ENCODE_RESTRICTED)
				rc = -EINVAL;		// Invalid
			// Commit the changes
			if (rc == 0)
				local->need_commit = 1;
			break;

		// Get the WEP keys and mode
		case SIOCGIWENCODE:
			// Is it supported?
			if (!wvlan_hw_getprivacy(&local->ifb))
			{
				rc = -EOPNOTSUPP;
				break;
			}
			// Only super-user can see WEP key
			if (!capable(CAP_NET_ADMIN))
			{
				rc = -EPERM;
				break;
			}
			// Basic checking...
			if (wrq->u.encoding.pointer != (caddr_t) 0)
			{
				int index = (wrq->u.encoding.flags & IW_ENCODE_INDEX) - 1;
				// Note: should read from adapter(?), and check if WEP capable
				// Set the flags
				wrq->u.encoding.flags = 0;
				if (local->wep_on == 0)
					wrq->u.encoding.flags |= IW_ENCODE_DISABLED;
				// Which key do we want
				if ((index < 0) || (index >= MAX_KEYS))
					index = local->transmit_key;
				wrq->u.encoding.flags |= index + 1;
				// Copy the key to the user buffer
				wrq->u.encoding.length = local->key[index].len;
				wv_driver_unlock(local, &flags);
				rc = copy_to_user(wrq->u.encoding.pointer, local->key[index].key, local->key[index].len);
				wv_driver_lock(local, &flags);
				if (rc)
					rc = -EFAULT;
				
			}
			break;
#endif /* WIRELESS_EXT > 8 */

#if WIRELESS_EXT > 9
		// Get the current Tx-Power
		case SIOCGIWTXPOW:
			wrq->u.txpower.value = 15;	/* 15 dBm */
			wrq->u.txpower.fixed = 1;	/* No power control */
			wrq->u.txpower.disabled = 0;	/* Can't turn off */
			wrq->u.txpower.flags = IW_TXPOW_DBM;
			break;
#endif /* WIRELESS_EXT > 9 */

		// Get range of parameters
		case SIOCGIWRANGE:
			if (wrq->u.data.pointer)
			{
				struct iw_range range;
				rc = verify_area(VERIFY_WRITE, wrq->u.data.pointer, sizeof(struct iw_range));
				if (rc)
					break;
				/* Set the length (very important for
				 * backward compatibility) */
				wrq->u.data.length = sizeof(range);

				/* Set all the info we don't care or
				 * don't know about to zero */
				memset(&range, 0, sizeof(range));

#if WIRELESS_EXT > 10
				/* Set the Wireless Extension versions */
				range.we_version_compiled = WIRELESS_EXT;
				range.we_version_source = 10;
#endif /* WIRELESS_EXT > 10 */

				// Throughput is no way near 2 Mb/s !
				// This value should be :
				//	1.6 Mb/s for the 2 Mb/s card
				//	~5 Mb/s for the 11 Mb/s card
				// Jean II
				range.throughput = 1.6 * 1024 * 1024;
				range.min_nwid = 0x0000;
				range.max_nwid = 0x0000;
				range.num_channels = 14;
				range.num_frequency = wvlan_hw_getfrequencylist(&local->ifb,
						      range.freq,
						      IW_MAX_FREQUENCIES);
				range.sensitivity = 3;
				if (local->port_type == 3 &&
				    local->spy_number == 0)
				{
					range.max_qual.qual = 0;
					range.max_qual.level = 0;
					range.max_qual.noise = 0;
				}
				else
				{
					range.max_qual.qual = 0x8b - 0x2f;
					range.max_qual.level = 0x2f - 0x95 - 1;
					range.max_qual.noise = 0x2f - 0x95 - 1;
				}
#if WIRELESS_EXT > 7
				range.num_bitrates = wvlan_getbitratelist(&local->ifb,
							range.bitrate,
							IW_MAX_BITRATES);
				range.min_rts = 0;
				range.max_rts = 2347;
				range.min_frag = 256;
				range.max_frag = 2346;
#endif	/* WIRELESS_EXT > 7 */
#if WIRELESS_EXT > 8
				// Is WEP it supported?
				if (wvlan_hw_getprivacy(&local->ifb))
				{
					// WEP: RC4 40 bits
					range.encoding_size[0] = MIN_KEY_SIZE;
					// RC4 ~128 bits
					range.encoding_size[1] = MAX_KEY_SIZE;
					range.num_encoding_sizes = 2;
					range.max_encoding_tokens = 4;	// 4 keys
				}
				else
				{
					range.num_encoding_sizes = 0;
					range.max_encoding_tokens = 0;
				}
#endif /* WIRELESS_EXT > 8 */
#if WIRELESS_EXT > 9
				/* Power Management */
				range.min_pmp = 0;		/* ??? */
				range.max_pmp = 65535000;	/* ??? */
				range.pmp_flags = IW_POWER_PERIOD;
				range.pmt_flags = 0;
				range.pm_capa = IW_POWER_PERIOD |
				  IW_POWER_UNICAST_R;
				/* Transmit Power */
				range.txpower[0] = 15;
				range.num_txpower = 1;
				range.txpower_capa = IW_TXPOW_DBM;
#endif /* WIRELESS_EXT > 9 */
				wv_driver_unlock(local, &flags);
				rc = copy_to_user(wrq->u.data.pointer, &range, sizeof(struct iw_range));
				wv_driver_lock(local, &flags);
				if (rc)
					rc = -EFAULT;
			}
			break;

#ifdef WIRELESS_SPY
		// Set the spy list
		case SIOCSIWSPY:
			if (wrq->u.data.length > IW_MAX_SPY)
			{
				rc = -E2BIG;
				break;
			}
			local->spy_number = wrq->u.data.length;
			if (local->spy_number > 0)
			{
				struct sockaddr address[IW_MAX_SPY];
				int i;
				rc = verify_area(VERIFY_READ, wrq->u.data.pointer, sizeof(struct sockaddr) * local->spy_number);
				if (rc)
					break;
				wv_driver_unlock(local, &flags);
				rc = copy_from_user(address, wrq->u.data.pointer, sizeof(struct sockaddr) * local->spy_number);
				wv_driver_lock(local, &flags);
				if (rc) {
					rc = -EFAULT;
					break;
				}
				for (i=0; i<local->spy_number; i++)
					memcpy(local->spy_address[i], address[i].sa_data, MAC_ADDR_SIZE);
				memset(local->spy_stat, 0, sizeof(struct iw_quality) * IW_MAX_SPY);
				DEBUG(DEBUG_INFO, "%s: New spy list:\n", dev_info);
				for (i=0; i<wrq->u.data.length; i++)
					DEBUG(DEBUG_INFO, "%s: %d - %02x:%02x:%02x:%02x:%02x:%02x\n", dev_info, i+1,
						local->spy_address[i][0], local->spy_address[i][1],
						local->spy_address[i][2], local->spy_address[i][3],
						local->spy_address[i][4], local->spy_address[i][5]);
			}
			break;

		// Get the spy list
		case SIOCGIWSPY:
			wrq->u.data.length = local->spy_number;
			if ((local->spy_number > 0) && (wrq->u.data.pointer))
			{
				struct sockaddr address[IW_MAX_SPY];
				int i;
				rc = verify_area(VERIFY_WRITE, wrq->u.data.pointer, (sizeof(struct iw_quality)+sizeof(struct sockaddr)) * IW_MAX_SPY);
				if (rc)
					break;
				for (i=0; i<local->spy_number; i++)
				{
					memcpy(address[i].sa_data, local->spy_address[i], MAC_ADDR_SIZE);
					address[i].sa_family = AF_UNIX;
				}
				wv_driver_unlock(local, &flags);
				rc = copy_to_user(wrq->u.data.pointer, address, sizeof(struct sockaddr) * local->spy_number);
				rc += copy_to_user(wrq->u.data.pointer + (sizeof(struct sockaddr)*local->spy_number), local->spy_stat, sizeof(struct iw_quality) * local->spy_number);
				wv_driver_lock(local, &flags);
				if (rc)
					rc = -EFAULT;

				for (i=0; i<local->spy_number; i++)
					local->spy_stat[i].updated = 0;
			}
			break;
#endif /* WIRELESS_SPY */

#ifdef HISTOGRAM
		// Set the histogram range
		case SIOCDEVPRIVATE + 0xd:
			// Only super-user can set histogram data
			if (!capable(CAP_NET_ADMIN))
			{
				rc = -EPERM;
				break;
			}
			if (wrq->u.data.length > 16)
			{
				rc = -E2BIG;
				break;
			}
			local->his_number = wrq->u.data.length;
			if (local->his_number > 0)
			{
				rc = verify_area(VERIFY_READ, wrq->u.data.pointer, sizeof(char) * local->his_number);
				if (rc)
					break;
				wv_driver_unlock(local, &flags);
				rc = copy_from_user(local->his_range, wrq->u.data.pointer, sizeof(char) * local->his_number);
				wv_driver_lock(local, &flags);
				if (rc) {
					rc = -EFAULT;
					break;
				}
				memset(local->his_sum, 0, sizeof(long) * 16);
			}
			break;

		// Get the histogram statistic
		case SIOCDEVPRIVATE + 0xe:
			wrq->u.data.length = local->his_number;
			if ((local->his_number > 0) && (wrq->u.data.pointer))
			{
				rc = verify_area(VERIFY_WRITE, wrq->u.data.pointer, sizeof(long) * 16);
				if (rc)
					break;
				wv_driver_unlock(local, &flags);
				rc = copy_to_user(wrq->u.data.pointer, local->his_sum, sizeof(long) * local->his_number);
				wv_driver_lock(local, &flags);
				if (rc)
					rc = -EFAULT;
			}
			break;
#endif /* HISTOGRAM */

		// Get valid private ioctl calls
		case SIOCGIWPRIV:
			if (wrq->u.data.pointer)
			{
				struct iw_priv_args priv[] = {
#ifdef HISTOGRAM
					{ SIOCDEVPRIVATE + 0xd, IW_PRIV_TYPE_BYTE | 16, 0, "sethisto" },
					{ SIOCDEVPRIVATE + 0xe, 0, IW_PRIV_TYPE_INT | 16, "gethisto" },
#endif
#ifdef PCMCIA_DEBUG
					{ SIOCDEVPRIVATE + 0x0, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "force_reset" },
					{ SIOCDEVPRIVATE + 0x1, IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1, 0, "debug_getinfo" },
#endif
				};
				rc = verify_area(VERIFY_WRITE, wrq->u.data.pointer, sizeof(priv));
				if (rc)
					break;
				wrq->u.data.length = sizeof(priv) / sizeof(priv[0]);
				wv_driver_unlock(local, &flags);
				rc = copy_to_user(wrq->u.data.pointer, priv, sizeof(priv));
				wv_driver_lock(local, &flags);
				if (rc)
					rc = -EFAULT;
			}
			break;

#ifdef PCMCIA_DEBUG
		// Force card reset (debug purpose only)
		case SIOCDEVPRIVATE + 0x0:
			// Only super-user can reset the card...
			if (!capable(CAP_NET_ADMIN))
			{
				rc = -EPERM;
				break;
			}
			if (*((int *) wrq->u.name) > 0)
			{
				// 'hard' reset
				printk(KERN_DEBUG "%s: Forcing hard reset\n", dev_info);
				/* IRQ already disabled, don't do it again */
				wvlan_hw_shutdown(dev);
				wvlan_hw_config(dev);
			}
			else
			{
				// 'soft' reset
				printk(KERN_DEBUG "%s: Forcing soft reset\n", dev_info);
				/* IRQ already disabled, don't do it again */
				wvlan_hw_reset(dev);
			}
			break;

		// Get info from card and dump answer to syslog (debug purpose only)
		case SIOCDEVPRIVATE + 0x1:
			{
				CFG_ID_STRCT ltv;
				char *p;
				int typ = *((int *) wrq->u.name);
				ltv.len = 18;
				ltv.typ = typ;
				rc = hcf_get_info(&local->ifb, (LTVP) &ltv);
				if (rc)
					printk(KERN_DEBUG "%s: hcf_get_info(0x%x) returned error 0x%x\n", dev_info, typ, rc);
				else
				{
					p = (char *) &ltv.id;
					printk(KERN_DEBUG "%s: hcf_get_info(0x%x) returned %d words:\n", dev_info, ltv.typ, ltv.len);
					printk(KERN_DEBUG "%s: hex-dump: ", dev_info);
					for (rc=0; rc<(ltv.len); rc++)
						printk("%04x ", le16_to_cpup(&ltv.id[rc]));
					printk("\n");
					printk(KERN_DEBUG "%s: ascii-dump: '", dev_info);
					for (rc=0; rc<(ltv.len*2); rc++)
						printk("%c", (p[rc]>31) ? p[rc] : '.');
					printk("'\n");
				}
			}
			break;
#endif /* PCMCIA_DEBUG */

		// All other calls are currently unsupported
		default:
			rc = -EOPNOTSUPP;
	}

	/* Some of the "set" function may have modified some of the
	 * parameters. It's now time to commit them in the card */
	if(local->need_commit) {
		/* Is the driver active ?
		 * Here, we optimise. If the driver is not active, we don't
		 * commit the individual changes, and all the changes will
		 * be committed together in wvlan_open(). This significantely
		 * speed up the card startup when using wireless.opts
		 * Jean II */
		if((local->link->open) || (cmd == SIOCSIWESSID)) {
			/* IRQ are already disabled */
			wvlan_hw_shutdown(dev);
			wvlan_hw_config(dev);
			local->need_commit = 0;
		}
	}

	// Re-enable interrupts
	wv_driver_unlock(local, &flags);

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_ioctl()\n");
	return rc;
}

struct iw_statistics *wvlan_get_wireless_stats (struct net_device *dev)
{
	struct net_local *local = (struct net_local *) dev->priv;
	CFG_COMMS_QUALITY_STRCT ltv;
	unsigned long flags;
	int rc;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_get_wireless_stats(%s)\n", dev->name);

	// Disable interrupts
	wv_driver_lock(local, &flags);

	local->wstats.status = 0;
	if (local->port_type != 3)
	{
		ltv.len = 4;
		ltv.typ = CFG_COMMS_QUALITY;
		rc = hcf_get_info(&local->ifb, (LTVP) &ltv);
		DEBUG(DEBUG_NOISY, "%s: hcf_get_info(CFG_COMMS_QUALITY) returned 0x%x\n", dev_info, rc);
		local->wstats.qual.qual = max(min(le16_to_cpup(&ltv.coms_qual), 0x8b-0x2f), 0);
		local->wstats.qual.level = max(min(le16_to_cpup(&ltv.signal_lvl), 0x8a), 0x2f) - 0x95;
		local->wstats.qual.noise = max(min(le16_to_cpup(&ltv.noise_lvl), 0x8a), 0x2f) - 0x95;
		local->wstats.qual.updated = 7;
	}
	else
	{
		// Quality levels cannot be determined in ad-hoc mode,
		// because we can 'hear' more that one remote station.
		// If a spy address is defined, we report stats of the
		// first spy address
		local->wstats.qual.qual = 0;
		local->wstats.qual.level = 0;
		local->wstats.qual.noise = 0;
		local->wstats.qual.updated = 0;
#ifdef WIRELESS_SPY
		if (local->spy_number > 0)
		{
			local->wstats.qual.qual = local->spy_stat[0].qual;
			local->wstats.qual.level = local->spy_stat[0].level;
			local->wstats.qual.noise = local->spy_stat[0].noise;
			local->wstats.qual.updated = local->spy_stat[0].updated;
		}
#endif /* WIRELESS_SPY */
	}

	// Packets discarded in the wireless adapter due to wireless specific problems
	local->wstats.discard.nwid = 0;
	local->wstats.discard.code = local->ifb.IFB_NIC_Tallies.RxWEPUndecryptable;
	local->wstats.discard.misc = local->ifb.IFB_NIC_Tallies.RxFCSErrors +
					local->ifb.IFB_NIC_Tallies.RxDiscards_NoBuffer +
					local->ifb.IFB_NIC_Tallies.TxDiscardsWrongSA;

	// Re-enable interrupts
	wv_driver_unlock(local, &flags);

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_get_wireless_stats()\n");
	return (&local->wstats);
}

#ifdef WIRELESS_SPY
static inline void wvlan_spy_gather (struct net_device *dev, u_char *mac, u_char *stats)
{
	struct net_local *local = (struct net_local *)dev->priv;
	int i;

	// Gather wireless spy statistics: for each packet, compare the
	// source address with out list, and if match, get the stats...
	for (i=0; i<local->spy_number; i++)
		if (!memcmp(mac, local->spy_address[i], MAC_ADDR_SIZE))
		{
			local->spy_stat[i].qual = stats[2];
			local->spy_stat[i].level = stats[0] - 0x95;
			local->spy_stat[i].noise = stats[1] - 0x95;
			local->spy_stat[i].updated = 7;
		}
}
#endif /* WIRELESS_SPY */

#ifdef HISTOGRAM
static inline void wvlan_his_gather (struct net_device *dev, u_char *stats)
{
	struct net_local *local = (struct net_local *)dev->priv;
	u_char level = stats[0] - 0x2f;
	int i;

	// Calculate a histogram of the signal level. Each time the
	// level goes into our defined set of interval, we increment
	// the count.
	i = 0;
	while ((i < (local->his_number-1)) && (level >= local->his_range[i++]));
	local->his_sum[i]++;
}
#endif /* HISTOGRAM */
#endif /* WIRELESS_EXT */

int wvlan_change_mtu (struct net_device *dev, int new_mtu)
{
	if (new_mtu < WVLAN_MIN_MTU || new_mtu > WVLAN_MAX_MTU)
	{
		DEBUG(DEBUG_INFO, "%s: New MTU of %d for %s out of range!\n", dev_info, new_mtu, dev->name);
		return -EINVAL;
	}
	dev->mtu = new_mtu;
	DEBUG(DEBUG_INFO, "%s: MTU of %s set to %d bytes\n", dev_info, dev->name, new_mtu);
	return 0;
}

static void wvlan_set_multicast_list (struct net_device *dev)
{
	struct net_local *local = (struct net_local *)dev->priv;
	unsigned long flags;

	// Note: check if hardware up & running?

	// Disable interrupts
	wv_driver_lock(local, &flags);

	DEBUG(DEBUG_INFO, "%s: setting multicast Rx mode %02X to %d addresses.\n", dev->name, dev->flags, dev->mc_count);

	// Ok, what do we want?
	if (dev->flags & IFF_PROMISC)
	{
		// Enable promiscuous mode: receive all packets.
		if (!local->promiscuous)
		{
			local->promiscuous = 1;
			local->mc_count = 0;
			wvlan_hw_setpromisc(&local->ifb, local->promiscuous);
			dev->flags |= IFF_PROMISC;
		}
	}
	else
		// If all multicast addresses
		// or too many multicast addresses for the hardware filter
		if ((dev->flags & IFF_ALLMULTI) || (dev->mc_count > WVLAN_MAX_MULTICAST))
		{
			// Disable promiscuous mode, but active the all multicast mode
			if (!local->promiscuous) {
				// The Wavelan IEEE doesn't seem to have a
				// "receive all multicast" flag, which allow to
				// grab all multicast frames. So we go for
				// promiscuous and let TCP filter packets,
				// which is *very* far from optimal.
				// Note that CNF_MCAST_RX is quite different,
				// as it specify if the Wavelan will wake up for
				// the broadcast announcements from the AP (DTIM)
				local->promiscuous = 1;
				local->mc_count = 0;
				wvlan_hw_setpromisc(&local->ifb, local->promiscuous);
				// Tell the kernel that we are doing a really bad job...
				dev->flags |= IFF_PROMISC;
			}
		}
		else
			// If there is some multicast addresses to send
			if (dev->mc_list != (struct dev_mc_list *) NULL)
			{
				// Disable promiscuous mode, but receive all packets
				// in multicast list
#ifdef MULTICAST_AVOID
				if (local->promiscuous || local->allmulticast || (dev->mc_count != local->mc_count))
#endif
				{
					struct dev_mc_list *dmi;
					int i;
					CFG_GROUP_ADDR_STRCT ltv;
					int rc;

					local->promiscuous = 0;
					local->mc_count = dev->mc_count;
					// Disable promiscuous
					wvlan_hw_setpromisc(&local->ifb, local->promiscuous);
					dev->flags &= ~IFF_PROMISC;
					// Write multicast addresses in the adapter
					for (i=0, dmi=dev->mc_list; dmi; dmi=dmi->next)
					memcpy(ltv.mac_addr[i++], dmi->dmi_addr, dmi->dmi_addrlen);
					ltv.len = (ETH_ALEN * local->mc_count / 2) + 1;
					ltv.typ = CFG_GROUP_ADDR;
					rc = hcf_put_info(&local->ifb, (LTVP) &ltv);
					DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_GROUP_ADDR:0x%x) returned 0x%x\n", dev_info, local->mc_count, rc);
				}
			}
			else
			{
				// Switch to normal mode: disable promiscuous mode and
				// clear the multicast list.
				if (local->promiscuous || local->mc_count != 0)
				{
					CFG_GROUP_ADDR_STRCT ltv;
					int rc;
					local->promiscuous = 0;
					local->mc_count = 0;
					wvlan_hw_setpromisc(&local->ifb, local->promiscuous);
					// Clear multicast list
					ltv.len = 1;
					ltv.typ = CFG_GROUP_ADDR;
					rc = hcf_put_info(&local->ifb, (LTVP) &ltv);
					DEBUG(DEBUG_NOISY, "%s: hcf_put_info(CFG_GROUP_ADDR:0x%x) returned 0x%x\n", dev_info, local->mc_count, rc);
				}
			}
	// Re-enable interrupts
	wv_driver_unlock(local, &flags);

	return;
}



/********************************************************************
 * NET TX / RX
 */
static void wvlan_watchdog (struct net_device *dev)
{
#ifdef WVLAN_RESET_ON_TX_TIMEOUT
	struct net_local *local = (struct net_local *) dev->priv;
	unsigned long flags;
#endif

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_wathdog(%s)\n", dev->name);

	// In theory, we could try to abort the current Tx command here,
	// this would avoid to go through a long reset process in many
	// cases (obstruction of the channel, very high contention)...

	// Reset card in case of Tx timeout
#ifdef WVLAN_RESET_ON_TX_TIMEOUT
	printk(KERN_WARNING "%s: %s Tx timed out! Resetting card\n", dev_info, dev->name);
	/* IRQ currently enabled, so disable it */
	wv_driver_lock(local, &flags);
	wvlan_hw_shutdown(dev);
	wvlan_hw_config(dev);
	wv_driver_unlock(local, &flags);
#else
	printk(KERN_WARNING "%s: %s Tx timed out! Ignoring...\n", dev_info, dev->name);
#endif

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_watchdog()\n");
}

int wvlan_tx (struct sk_buff *skb, struct net_device *dev)
{
	struct net_local *local = (struct net_local *)dev->priv;
	unsigned long flags;
	int rc, len;
	u_char *p;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_tx(%s)\n", dev->name);

#if (KERNEL_VERSION_CODE < KERNEL_VERSION(2,3,42))
	// We normally shouldn't be called if queue is stopped (transmitter busy)
	// but older kernel code does anyway. So we'll check if the last
	// transmission has timed out and reset the device in case
	if (netif_queue_stopped(dev))
	{
		DEBUG(DEBUG_TXRX, "%s: wvlan_tx(%s) called while busy!\n", dev_info, dev->name);
		if ((jiffies - dev->trans_start) < TX_TIMEOUT)
			return 1;
		if (!netif_running(dev))
		{
			printk(KERN_WARNING "%s: %s Tx on stopped device!\n", dev_info, dev->name);
			return 1;
		}
		wvlan_watchdog(dev);
	}
#endif

	skb_tx_check(dev, skb);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,79))
	skb->arp = 1;
#endif

	// Tell queueing layer to stop sending
	// TODO: We should use multiple Tx buffers and
	// re-enable the queue (netif_wake_queue()) if
	// there's space left in the Tx buffers.
	netif_stop_queue(dev);

	// Disable interrupts
	wv_driver_lock(local, &flags);

	// Prepare packet
	p = skb->data;
	len = (ETH_ZLEN < skb->len) ? skb->len : ETH_ZLEN;

	// Add Ethernet-II frame encapsulation, because
	// HCF-light doesn't support that.
	if (p[13] + (p[12] << 8) > 1500)
	{
		hcf_put_data(&local->ifb, p, 12, 0);
		len += sizeof(snap_header);
		snap_header[1] = (len-0x0e) & 0xff;
		snap_header[0] = (char)((len-0x0e) >> 8);
		hcf_put_data(&local->ifb, snap_header, sizeof(snap_header), 0);
		hcf_put_data(&local->ifb, p+12, len-12-sizeof(snap_header), 0);
	}
	else
		hcf_put_data(&local->ifb, p, len, 0);

	// Send packet
	rc = hcf_send(&local->ifb, 0);

	// Remeber time transmission and count tx bytes
	dev->trans_start = jiffies;
	add_tx_bytes(&local->stats, len);

	// Re-enable interrupts
	wv_driver_unlock(local, &flags);

	// It might be no good idea doing a printk() debug output during
	// disabled interrupts (I'm not sure...). So better do it here.
	DEBUG(DEBUG_TXRX, "%s: Sending 0x%x octets\n", dev_info, len);
	DEBUG(DEBUG_NOISY, "%s: hcf_send() returned 0x%x\n", dev_info, rc);

	DEV_KFREE_SKB(skb);
	DEBUG(DEBUG_CALLTRACE, "<- wvlan_tx()\n");
	return 0;
}

void wvlan_rx (struct net_device *dev, int len)
{
	struct net_local *local = (struct net_local *)dev->priv;
	struct sk_buff *skb;
	u_char *p;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_rx(%s)\n", dev->name);

	// Create skb packet
	skb = dev_alloc_skb(len+2);
	if (!skb)
	{
		printk(KERN_WARNING "%s: %s Rx cannot allocate buffer for new packet\n", dev_info, dev->name);
		local->stats.rx_dropped++;
		return;
	}
	DEBUG(DEBUG_TXRX, "%s: Receiving 0x%x octets\n", dev_info, len);

	// Align IP on 16b boundary
	skb_reserve(skb, 2);
	p = skb_put(skb, len);
	dev->last_rx = jiffies;

	// Add Ethernet-II frame decapsulation, because
	// HCF-light doesn't support that.
	if (local->ifb.IFB_RxStat == 0x2000 || local->ifb.IFB_RxStat == 0x4000)
	{
		hcf_get_data(&local->ifb, 0, p, 12);
		hcf_get_data(&local->ifb, 12+sizeof(snap_header), p+12, len-12-sizeof(snap_header));
		skb_trim(skb, len-sizeof(snap_header));
	}
	else
		hcf_get_data(&local->ifb, 0, p, len);

	skb->dev = dev;
	skb->protocol = eth_type_trans(skb, dev);
	skb->ip_summed = CHECKSUM_NONE;

	// Hand the packet over to the kernel
	netif_rx(skb);
	local->stats.rx_packets++;
	add_rx_bytes(&local->stats, len);

#ifdef WIRELESS_EXT
#if defined(WIRELESS_SPY) || defined(HISTOGRAM)
	if (
#ifdef WIRELESS_SPY
		(local->spy_number > 0) ||
#endif
#ifdef HISTOGRAM
		(local->his_number > 0) ||
#endif
		0 )
	{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(1,3,0))
		char *srcaddr = skb->mac.raw + MAC_ADDR_SIZE;
#else
		char *srcaddr = skb->data + MAX_ADDR_SIZE;
#endif
		u_char stats[3];
		int rc, i;
		local->wstats.status = 0;

		// Using spy support with port_type==1 will really
		// slow down everything, because the signal quality
		// must be queried for each packet here.
		// If the user really asks for it (set some address in the
		// spy list), we do it, but he will pay the price.
		// Note that to get here, you need both WIRELESS_SPY
		// compiled in AND some addresses in the list !!!
		// TODO: Get and cache stats here so that they
		// are available but don't need to be retreived
		// every time a packet is received.
#if defined(HISTOGRAM)
		// We can't be clever...
		rc = hcf_get_data(&local->ifb, HFS_Q_INFO, stats, 2);
		DEBUG(DEBUG_NOISY, "%s: hcf_get_data(HFS_Q_INFO) returned 0x%x\n", dev_info, rc);
#else // Therefore WIRELESS_SPY only !!!
		memset(&stats, 0, sizeof(stats));
		// Query only for addresses in our list !
		for (i=0; i<local->spy_number; i++)
			if (!memcmp(srcaddr, local->spy_address[i], MAC_ADDR_SIZE))
			{
				rc = hcf_get_data(&local->ifb, HFS_Q_INFO, stats, 2);
				break;
			}
#endif
		stats[2] = stats[0];
		stats[0] = max(min(stats[1], 0x8a), 0x2f);
		stats[1] = max(min(stats[2], 0x8a), 0x2f);
		stats[2] = stats[0] - stats[1];
#ifdef WIRELESS_SPY
		wvlan_spy_gather(dev, srcaddr, stats);  
#endif
#ifdef HISTOGRAM
		wvlan_his_gather(dev, stats);
#endif
	}
#endif /* WIRELESS_SPY || HISTOGRAM */
#endif /* WIRELESS_EXT */

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_rx()\n");
}


/********************************************************************
 * NET OPEN / CLOSE
 */

static int wvlan_open (struct net_device *dev)
{
	struct net_local *local = (struct net_local *) dev->priv;
	struct dev_link_t *link = local->link;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_open(%s)\n", dev->name);

	/* Check if we need to re-setup the card */
	if(local->need_commit) {
		unsigned long flags;
		wv_driver_lock(local, &flags);
		wvlan_hw_shutdown(dev);
		wvlan_hw_config(dev);
		local->need_commit = 0;
		wv_driver_unlock(local, &flags);
	}	

	// TODO: Power up the card here and power down on close?
	// For now this is done on device init, not on open
	// Might be better placed here so that some settings can
	// be made by shutting down the device without removing
	// the driver (iwconfig).
	// But this is no real problem for now :-)

	// Start reception and declare the driver ready
	if (!local->ifb.IFB_CardStat)
		return -ENODEV;
	netif_device_attach(dev);
	netif_start_queue(dev);
	local->interrupt = 0;
	link->open++;
	MOD_INC_USE_COUNT;

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_open()\n");
	return 0;
}

static int wvlan_close (struct net_device *dev)
{
	struct net_local *local = (struct net_local *) dev->priv;
	struct dev_link_t *link = local->link;

	// If the device isn't open, then nothing to do
	if (!link->open)
	{
		DEBUG(DEBUG_CALLTRACE, "<> wvlan_close(%s)\n", dev->name);
		return 0;
	}

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_close(%s)\n", dev->name);

	// Close the device
	link->open--;
	MOD_DEC_USE_COUNT;

	// Check if card is still present
	if (netif_running(dev))
	{
		netif_stop_queue(dev);
		netif_device_detach(dev);
		// TODO: Shutdown hardware (see wvlan_open)
	}
	else
		if (link->state & DEV_STALE_CONFIG)
			mod_timer(&link->release, jiffies + HZ/20);

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_close()\n");
	return -EINVAL;
}


/********************************************************************
 * INTERRUPT HANDLER
 */
static void wvlan_interrupt (int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = (struct net_device *) dev_id;
	struct net_local *local = (struct net_local *) dev->priv;
	int rc, cnt, ev, len;

	DEBUG(DEBUG_INTERRUPT, "-> wvlan_interrupt(%d)\n", irq);

	// Check device
	if (!dev)
	{
		printk(KERN_WARNING "%s: IRQ %d for unknown device!\n", dev_info, irq);
		return;
	}

	/* Prevent reentrancy. We need to do that because we may have
	 * multiple interrupt handler running concurently.
	 * It is safe because wv_driver_lock() disable interrupts before
	 * aquiring the spinlock. */
	spin_lock(&local->slock);

	// Turn off interrupts
	rc = hcf_action(&local->ifb, HCF_ACT_INT_OFF);
	DEBUG(DEBUG_NOISY, "%s: hcf_action(HCF_ACT_INT_OFF) returned 0x%x\n", dev_info, rc);
	/* Check state of interrupt */
	if (test_and_set_bit(0, (void *)&local->interrupt))
		printk(KERN_DEBUG "%s: Warning: IRQ %d Reentering interrupt handler!\n", dev_info, irq);

	// Process pending interrupts.
	// We continue until hcf_service_nic tells that no received
	// frames are pending. However we should check to not lock up
	// here in an endless loop.
	cnt = 7;
	while (cnt--)
	{
		// Ask NIC why interrupt occurred
		ev = hcf_service_nic(&local->ifb);
		DEBUG(DEBUG_NOISY, "%s: hcf_service_nic() returned 0x%x RscInd 0x%x\n", dev_info, ev, local->ifb.IFB_PIFRscInd);

		// Transmission completion seem to be also signalled with ev==0
		// better check that out with RscInd and complete transfer also
		if (local->ifb.IFB_PIFRscInd && netif_queue_stopped(dev))
			ev |= HREG_EV_TX;

		// HREG_EV_TICK: WMAC controller auxiliary timer tick
		if (ev & HREG_EV_TICK)
		{
			DEBUG(DEBUG_INFO,"%s: Auxiliary timer tick\n", dev_info);
		}

		// HREG_EV_RES: WMAC controller H/W error (wait timeout)
		if (ev & HREG_EV_RES)
		{
			// This message seems to occur often on heavy load
			// but it seem to don't have any effects on transmission
			// so we simply ignore it.
			//printk(KERN_WARNING "%s: WMAC H/W error (wait timeout, ignoring)!\n", dev_info);
		}

		// HREG_EV_INFO_DROP: WMAC did not have sufficient RAM to build unsollicited frame
		if (ev & HREG_EV_INFO_DROP)
			printk(KERN_WARNING "%s: WMAC did not have sufficient RAM to build unsollicited frame!\n", dev_info);

		// HREG_EV_INFO: WMAC controller asynchronous information frame
		if (ev & HREG_EV_INFO)
		{
			DEBUG(DEBUG_INFO, "%s: WMAC controller asynchronous information frame\n", dev_info);
		}

		// HREG_EV_CMD: WMAC controller command completed, status and response available
		//	unnecessary to handle here, it's handled by polling in HCF

		// HREG_EV_ALLOC: WMAC controller asynchronous part of allocation/reclaim completed
		//	also unnecessary to handle here, it's handled by polling in HCF

		// HREG_EV_TX_EXC: WMAC controller asynchronous transmission unsuccessful completed
		if (ev & HREG_EV_TX_EXC)
		{
			printk(KERN_WARNING "%s: WMAC controller asynchronous transmission unsuccessful completed\n", dev_info);
			local->stats.tx_errors++;
			netif_wake_queue(dev);
		}

		// HREG_EV_TX: WMAC controller asynchronous transmission successful completed
		if (ev & HREG_EV_TX)
		{
			DEBUG(DEBUG_TXRX, "%s: Transmission successful completed\n", dev_info);
			local->stats.tx_packets++;
			netif_wake_queue(dev);
		}

		// HREG_EV_RX: WMAC controller asynchronous receive frame
		// Break loop if no frame was received.
		if (!(ev & HREG_EV_RX))
			break;

		// If a frame was received, we process it and wrap back
		// up to the top of the while() loop so that hcf_service_nic()
		// gets called again after the frame drained from the NIC.
		// This allows us to find out if yet another frame has
		// arrived, and also to immediately acknowledge the just-
		// processed frame so that the NIC's buffer gets de-
		// allocated right away.
		len = local->ifb.IFB_RxLen;
		if (len)
		{
			DEBUG(DEBUG_INTERRUPT, "%s: Frame received. rx_len=0x%x\n", dev_info, len);
			wvlan_rx(dev, len);
		}
	}
	if (!cnt)
		printk(KERN_WARNING "%s: Maximum interrupt loops reached!\n", dev_info);

	// From now on, we don't care if we re-enter the interrupt handler
	local->interrupt = 0;

	// Turn back interrupts on (unlock)
	rc = hcf_action(&local->ifb, HCF_ACT_INT_ON);
	DEBUG(DEBUG_NOISY, "%s: hcf_action(HCF_ACT_INT_ON) returned 0x%x\n", dev_info, rc);

	/* Release spinlock */
	spin_unlock (&local->slock);

	DEBUG(DEBUG_INTERRUPT, "<- wvlan_interrupt()\n");
}


/********************************************************************
 * PCMCIA CONFIG / RELEASE
 */
#define CS_CHECK(fn, args...) while ((last_ret=CardServices(last_fn=(fn),args))!=0) goto cs_failed
#define CFG_CHECK(fn, args...) if (CardServices(fn, args) != 0) goto next_entry
static int wvlan_config (dev_link_t *link)
{
	client_handle_t handle = link->handle;
	tuple_t tuple;
	cisparse_t parse;
	struct net_device *dev = (struct net_device *) link->priv;
	struct net_local *local = (struct net_local *) dev->priv;
	int last_fn, last_ret;
	u_char buf[64];
	win_req_t req;
	memreq_t map;
	int rc, i;
	config_info_t config;
	cistpl_cftable_entry_t dflt = { 0 };

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_config(0x%p)\n", link);

	// This reads the card's CONFIG tuple to find its configuration registers.
	tuple.DesiredTuple = CISTPL_CONFIG;
	tuple.Attributes = 0;
	tuple.TupleData = buf;
	tuple.TupleDataMax = sizeof(buf);
	tuple.TupleOffset = 0;
	CS_CHECK(GetFirstTuple, handle, &tuple);
	CS_CHECK(GetTupleData, handle, &tuple);
	CS_CHECK(ParseTuple, handle, &tuple, &parse);
	link->conf.ConfigBase = parse.config.base;
	link->conf.Present = parse.config.rmask[0];

	// Configure card
	link->state |= DEV_CONFIG;

	// Use card's current Vcc setting
	CS_CHECK(GetConfigurationInfo, handle, &config);
	link->conf.Vcc = config.Vcc;

	// In this loop, we scan the CIS for configuration table entries,
	// each of which describes a valid card configuration, including
	// voltage, IO window, memory window, and interrupt settings.
	// We make no assumptions about the card to be configured: we use
	// just the information available in the CIS.  In an ideal world,
	// this would work for any PCMCIA card, but it requires a complete
	// and accurate CIS.  In practice, a driver usually "knows" most of
	// these things without consulting the CIS, and most client drivers
	// will only use the CIS to fill in implementation-defined details.
	tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
	CS_CHECK(GetFirstTuple, handle, &tuple);
	while (1) {
		cistpl_cftable_entry_t *cfg = &(parse.cftable_entry);
		CFG_CHECK(GetTupleData, handle, &tuple);
		CFG_CHECK(ParseTuple, handle, &tuple, &parse);

		if (cfg->index == 0) goto next_entry;
		link->conf.ConfigIndex = cfg->index;

		// Does this card need audio output?
		if (cfg->flags & CISTPL_CFTABLE_AUDIO)
		{
			link->conf.Attributes |= CONF_ENABLE_SPKR;
			link->conf.Status = CCSR_AUDIO_ENA;
		}
	
		// Use power settings for Vpp if present
		// Note that the CIS values need to be rescaled

		if (cfg->vpp1.present & (1<<CISTPL_POWER_VNOM))
			link->conf.Vpp1 = link->conf.Vpp2 = cfg->vpp1.param[CISTPL_POWER_VNOM]/10000;
		else if (dflt.vpp1.present & (1<<CISTPL_POWER_VNOM))
			link->conf.Vpp1 = link->conf.Vpp2 = dflt.vpp1.param[CISTPL_POWER_VNOM]/10000;

		// Do we need to allocate an interrupt?
		if (cfg->irq.IRQInfo1 || dflt.irq.IRQInfo1)
			link->conf.Attributes |= CONF_ENABLE_IRQ;

		// IO window settings
		link->io.NumPorts1 = link->io.NumPorts2 = 0;
		if ((cfg->io.nwin > 0) || (dflt.io.nwin > 0)) {
			cistpl_io_t *io = (cfg->io.nwin) ? &cfg->io : &dflt.io;
			link->io.Attributes1 = IO_DATA_PATH_WIDTH_AUTO;
			if (!(io->flags & CISTPL_IO_8BIT))
				link->io.Attributes1 = IO_DATA_PATH_WIDTH_16;
			if (!(io->flags & CISTPL_IO_16BIT))
				link->io.Attributes1 = IO_DATA_PATH_WIDTH_8;
			link->io.BasePort1 = io->win[0].base;
			link->io.NumPorts1 = io->win[0].len;
			if (io->nwin > 1) {
				link->io.Attributes2 = link->io.Attributes1;
				link->io.BasePort2 = io->win[1].base;
				link->io.NumPorts2 = io->win[1].len;
			}
		}

		// This reserves IO space but doesn't actually enable it
		CFG_CHECK(RequestIO, link->handle, &link->io);

		// Now set up a common memory window, if needed.  There is room
		// in the dev_link_t structure for one memory window handle,
		// but if the base addresses need to be saved, or if multiple
		// windows are needed, the info should go in the private data
		// structure for this device.
		// Note that the memory window base is a physical address, and
		// needs to be mapped to virtual space with ioremap() before it
		// is used.
		if ((cfg->mem.nwin > 0) || (dflt.mem.nwin > 0)) {
			cistpl_mem_t *mem = (cfg->mem.nwin) ? &cfg->mem : &dflt.mem;
			req.Attributes = WIN_DATA_WIDTH_16|WIN_MEMORY_TYPE_CM;
			req.Base = mem->win[0].host_addr;
			req.Size = mem->win[0].len;
			req.AccessSpeed = 0;
			link->win = (window_handle_t)link->handle;
			CFG_CHECK(RequestWindow, &link->win, &req);
			map.Page = 0; map.CardOffset = mem->win[0].card_addr;
			CFG_CHECK(MapMemPage, link->win, &map);
		}

		// If we got this far, we're cool!
		break;

next_entry:
		if (cfg->flags & CISTPL_CFTABLE_DEFAULT)
			dflt = *cfg;
		CS_CHECK(GetNextTuple, handle, &tuple);
	}

	// Allocate an interrupt line.  Note that this does not assign a
	// handler to the interrupt, unless the 'Handler' member of the
	// irq structure is initialized.
	if (link->conf.Attributes & CONF_ENABLE_IRQ)
	{
		link->irq.Attributes = IRQ_TYPE_EXCLUSIVE | IRQ_HANDLE_PRESENT;
		link->irq.IRQInfo1 = IRQ_INFO2_VALID | IRQ_LEVEL_ID;
		if (irq_list[0] == -1)
			link->irq.IRQInfo2 = irq_mask;
		else
			for (i=0; i<4; i++)
				link->irq.IRQInfo2 |= 1 << irq_list[i];
		link->irq.Handler = wvlan_interrupt;
		link->irq.Instance = dev;
		CS_CHECK(RequestIRQ, link->handle, &link->irq);
	}

	// This actually configures the PCMCIA socket -- setting up
	// the I/O windows and the interrupt mapping, and putting the
	// card and host interface into "Memory and IO" mode.
	CS_CHECK(RequestConfiguration, link->handle, &link->conf);

	// Feed the netdevice with this info
	dev->irq = link->irq.AssignedIRQ;
	dev->base_addr = link->io.BasePort1;
	netif_start_queue(dev);

	// Report what we've done
	printk(KERN_INFO "%s: index 0x%02x: Vcc %d.%d", dev_info, link->conf.ConfigIndex, link->conf.Vcc/10, link->conf.Vcc%10);
	if (link->conf.Vpp1)
		printk(", Vpp %d.%d", link->conf.Vpp1/10, link->conf.Vpp1%10);
	if (link->conf.Attributes & CONF_ENABLE_IRQ)
		printk(", irq %d", link->irq.AssignedIRQ);
	if (link->io.NumPorts1)
		printk(", io 0x%04x-0x%04x", link->io.BasePort1, link->io.BasePort1+link->io.NumPorts1-1);
	if (link->io.NumPorts2)
		printk(" & 0x%04x-0x%04x", link->io.BasePort2, link->io.BasePort2+link->io.NumPorts2-1);
	if (link->win)
		printk(", mem 0x%06lx-0x%06lx", req.Base, req.Base+req.Size-1);
	printk("\n");

	link->state &= ~DEV_CONFIG_PENDING;

	// Make netdevice's name (if not ethX) and remember the device
	// Not very efficient here, this should go somewhere into dev_list,
	// but it works for now (taken from register_netdevice in kernel)
	/* Note : may fail if other drivers are also using this name */
	if(!eth)
	{
		for (i=0; i<MAX_WVLAN_CARDS; ++i)
			if (!wvlandev_index[i])
			{
				sprintf(dev->name, "wvlan%d", i);
				wvlandev_index[i] = dev;
				break;
			}
	}

	// Register the netdevice
	rc = register_netdev(dev);
	if (rc)
	{
		printk(KERN_WARNING "%s: register_netdev() failed!\n", dev_info);
		wvlan_release((u_long)link);
		return 0;
	}
	printk(KERN_INFO "%s: Registered netdevice %s\n", dev_info, dev->name);

	copy_dev_name(local->node, dev);
	link->dev = &local->node;

	// Success!
	DEBUG(DEBUG_CALLTRACE, "<- wvlan_config()\n");
	return 1;

cs_failed:
	cs_error(link->handle, last_fn, last_ret);
	wvlan_release((u_long)link);
	DEBUG(DEBUG_CALLTRACE, "<- wvlan_config()\n");
	return 0;
}

static void wvlan_release (u_long arg)
{
	dev_link_t *link = (dev_link_t *) arg;
	struct net_device *dev = (struct net_device *) link->priv;
	struct net_local *local = (struct net_local *) dev->priv;
	unsigned long flags;
	int i;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_release(0x%p)\n", link);

	// If the device is currently in use, we won't release
	// until it's actually closed.
	if (link->open)
	{
		DEBUG(DEBUG_INFO, "%s: wvlan_release: release postponed, %s still locked\n", dev_info, link->dev->dev_name);
		link->state |= DEV_STALE_CONFIG;
		return;
	}

	// Power down - IRQ currently enabled, so disable it
	wv_driver_lock(local, &flags);
	wvlan_hw_shutdown(dev);
	wv_driver_unlock(local, &flags);

	// Remove our device from index (only devices named wvlanX)
	for (i=0; i<MAX_WVLAN_CARDS; ++i)
		if (wvlandev_index[i] == dev)
		{
			wvlandev_index[i] = NULL;
			break;
		}

	if (link->win)
		CardServices(ReleaseWindow, link->win);
	CardServices(ReleaseConfiguration, link->handle);
	if (link->io.NumPorts1)
		CardServices(ReleaseIO, link->handle, &link->io);
	if (link->irq.AssignedIRQ)
		CardServices(ReleaseIRQ, link->handle, &link->irq);

	link->state &= ~DEV_CONFIG;

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_release()\n");
}


/********************************************************************
 * PCMCIA ATTACH / DETACH
 */
static dev_link_t *wvlan_attach (void)
{
	dev_link_t *link;
	struct net_device *dev;
	struct net_local *local;
	int rc;
	client_reg_t client_reg;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_attach()\n");

	// Flush stale links
	for (link=dev_list; link; link=link->next)
		if (link->state & DEV_STALE_LINK)
			wvlan_detach(link);

	// Initialize the dev_link_t structure
	link = kmalloc(sizeof(struct dev_link_t), GFP_KERNEL);
	memset(link, 0, sizeof(struct dev_link_t));
	link->release.function = &wvlan_release;
	link->release.data = (u_long) link;
	link->conf.IntType = INT_MEMORY_AND_IO;

	// Allocate space for netdevice (private data of link)
	dev = kmalloc(sizeof(struct net_device), GFP_KERNEL);
	memset(dev, 0, sizeof(struct net_device));
	link->priv = dev;

	// Allocate space for netdevice priv (private data of netdevice)
	local = kmalloc(sizeof(struct net_local), GFP_KERNEL);
	memset(local, 0, sizeof(struct net_local));
	dev->priv = local;

	// Initialize specific data
	local->link = link;
	local->dev = dev;
	spin_lock_init(&local->slock);
	// Copy modules parameters to private struct
	local->port_type = port_type;
	local->allow_ibss = allow_ibss;
	strcpy(local->network_name, network_name);
	local->channel = channel;
	// Initialise Wireless Extension stuff
#ifdef WIRELESS_EXT
	local->station_name[0] = '\0';
	local->ap_density = 1;
	local->medium_reservation = 2347;
	local->frag_threshold = 2346;
	local->mwo_robust = 0;
	local->transmit_rate = 3;
	local->wep_on = 0;
	local->pm_on = 0;
	local->pm_multi = 1;
	local->pm_period = 100000;
	// Check obsolete module parameters
	if(*(station_name)) {
		strcpy(local->station_name, station_name);
		printk(KERN_INFO "%s: ``station_name'' is an obsolete module parameter, please use iwconfig.", dev_info);
	}
#endif /* WIRELESS_EXT */

	// Standard setup for generic data
	ether_setup(dev);

	// kernel callbacks
	dev->open = wvlan_open;
	dev->stop = wvlan_close;
	dev->hard_start_xmit = wvlan_tx;
	dev->get_stats = wvlan_get_stats;
#ifdef WIRELESS_EXT
	dev->do_ioctl = wvlan_ioctl;
	dev->get_wireless_stats = wvlan_get_wireless_stats;
#endif /* WIRELESS_EXT */
	dev->change_mtu = wvlan_change_mtu;
	dev->set_multicast_list = wvlan_set_multicast_list;
//	dev->set_mac_address = wvlan_set_mac_address;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,3,42))
	dev->tx_timeout = &wvlan_watchdog;
	dev->watchdog_timeo = TX_TIMEOUT;
#endif

	// Other netdevice data
	init_dev_name(dev, local->node);
	dev->mtu = mtu;
	netif_stop_queue(dev);

	// Register with CardServices
	link->next = dev_list;
	dev_list = link;
	client_reg.dev_info = &dev_info;
	client_reg.Attributes = INFO_IO_CLIENT;
	client_reg.EventMask =	CS_EVENT_REGISTRATION_COMPLETE |
				CS_EVENT_CARD_INSERTION | CS_EVENT_CARD_REMOVAL |
				CS_EVENT_RESET_PHYSICAL | CS_EVENT_CARD_RESET |
				CS_EVENT_PM_SUSPEND | CS_EVENT_PM_RESUME;
	client_reg.event_handler = &wvlan_event;
	client_reg.Version = 0x0210;
	client_reg.event_callback_args.client_data = link;

	rc = CardServices(RegisterClient, &link->handle, &client_reg);
	if (rc)
	{
		cs_error(link->handle, RegisterClient, rc);
		wvlan_detach(link);
		return NULL;
	}

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_attach()\n");
	return link;
}

static void wvlan_detach (dev_link_t *link)
{
	dev_link_t **linkp;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_detach(0x%p)\n", link);

	// Locate device structure
	for (linkp=&dev_list; *linkp; linkp=&(*linkp)->next)
		if (*linkp == link)
			break;
	if (!*linkp)
	{
		printk(KERN_WARNING "%s: Attempt to detach non-existing PCMCIA client!\n", dev_info);
		return;
	}

	// If the device is currently configured and active, we won't
	// actually delete it yet. Instead, it is marked so that when the
	// release() function is called, that will trigger a proper
	// detach()
	del_timer(&link->release);
	if (link->state & DEV_CONFIG)
	{
		DEBUG(DEBUG_INFO, "%s: wvlan_detach: detach postponed, %s still locked\n", dev_info, link->dev->dev_name);
		wvlan_release((u_long)link);
		if (link->state & DEV_STALE_CONFIG)
		{
			link->state |= DEV_STALE_LINK;
			return;
		}
	}

	// Break the line with CardServices
	if (link->handle)
		CardServices(DeregisterClient, link->handle);

	// Unlink device structure, free pieces
	*linkp = link->next;
	if (link->priv)
	{
		struct net_device *dev = (struct net_device *) link->priv;
		if (link->dev)
		{
			unregister_netdev(dev);
			DEBUG(DEBUG_INFO, "%s: Netdevice unregistered\n", dev_info);
		}
		if (dev->priv)
			kfree(dev->priv);
		kfree(link->priv);
	}
	kfree(link);

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_detach()\n");
}


/********************************************************************
 * PCMCIA EVENT HANDLER
 */
static int wvlan_event (event_t event, int priority, event_callback_args_t *args)
{
	dev_link_t *link = (dev_link_t *) args->client_data;
	struct net_device *dev = (struct net_device *) link->priv;

	DEBUG(DEBUG_CALLTRACE, "-> wvlan_event(%s, %d, 0x%p)\n",
		((event==CS_EVENT_REGISTRATION_COMPLETE) ? "registration complete" :
		((event==CS_EVENT_CARD_INSERTION) ? "card insertion" :
		((event==CS_EVENT_CARD_REMOVAL) ? "card removal" :
		((event==CS_EVENT_RESET_PHYSICAL) ? "physical physical" :
		((event==CS_EVENT_CARD_RESET) ? "card reset" :
		((event==CS_EVENT_PM_SUSPEND) ? "pm suspend" :
		((event==CS_EVENT_PM_RESUME) ? "pm resume" :
		"unknown"))))))), priority, args);

	switch (event)
	{
		case CS_EVENT_CARD_INSERTION:
			link->state |= DEV_PRESENT | DEV_CONFIG_PENDING;
			if (!wvlan_config(link) || wvlan_hw_config_locked(dev))
				dev->irq = 0;
			break;

		case CS_EVENT_CARD_REMOVAL:
			link->state &= ~DEV_PRESENT;
			if (link->state & DEV_CONFIG)
			{
				netif_stop_queue(dev);
				netif_device_detach(dev);
				mod_timer(&link->release, jiffies + HZ/20);
			}
			break;

		case CS_EVENT_PM_SUSPEND:
			link->state |= DEV_SUSPEND;
		case CS_EVENT_RESET_PHYSICAL:
			if (link->state & DEV_CONFIG)
			{
				if (link->open)
				{
					netif_stop_queue(dev);
					netif_device_detach(dev);
				}
				CardServices(ReleaseConfiguration, link->handle);
			}
			break;

		case CS_EVENT_PM_RESUME:
			link->state &= ~DEV_SUSPEND;
			// Fall through
		case CS_EVENT_CARD_RESET:
			if (link->state & DEV_CONFIG)
			{
				CardServices(RequestConfiguration, link->handle, &link->conf);
				if (link->open)
				{
					struct net_local *local =
					  (struct net_local *) dev->priv;
					unsigned long flags;

					/* IRQ currently enabled,
					 * so disable it */
					wv_driver_lock(local, &flags);
					wvlan_hw_shutdown(dev);
					wvlan_hw_config(dev);
					wv_driver_unlock(local, &flags);
					netif_device_attach(dev);
					netif_start_queue(dev);
				}
			}
			break;
	}

	DEBUG(DEBUG_CALLTRACE, "<- wvlan_event()\n");
	return 0;
}


/********************************************************************
 * MODULE INSERTION / REMOVAL
 */
extern int __init init_wvlan_cs (void)
{
	servinfo_t serv;

	DEBUG(DEBUG_CALLTRACE, "-> init_module()\n");

	printk(KERN_INFO "%s: WaveLAN/IEEE PCMCIA driver v%s\n", dev_info, version);
	printk(KERN_INFO "%s: (c) Andreas Neuhaus <andy@fasta.fh-dortmund.de>\n", dev_info);

	// Check CardServices release
	CardServices(GetCardServicesInfo, &serv);
	if (serv.Revision != CS_RELEASE_CODE)
	{
		printk(KERN_WARNING "%s: CardServices release does not match!\n", dev_info);
		return -1;
	}

	// Register PCMCIA driver
	register_pcmcia_driver(&dev_info, &wvlan_attach, &wvlan_detach);

	DEBUG(DEBUG_CALLTRACE, "<- init_module()\n");
	return 0;
}

extern void __exit exit_wvlan_cs (void)
{
	DEBUG(DEBUG_CALLTRACE, "-> cleanup_module()\n");

	// Unregister PCMCIA driver
	unregister_pcmcia_driver(&dev_info);

	// Remove leftover devices
	if (dev_list)
		DEBUG(DEBUG_INFO, "%s: Removing leftover devices!\n", dev_info);
	while (dev_list)
	{
		if (dev_list->state & DEV_CONFIG)
			wvlan_release((u_long)dev_list);
		wvlan_detach(dev_list);
	}

	printk(KERN_INFO "%s: Driver unloaded\n", dev_info);
	DEBUG(DEBUG_CALLTRACE, "<- cleanup_module()\n");
}

module_init(init_wvlan_cs);
module_exit(exit_wvlan_cs);

/********************************************************************
 * EOF
 */
