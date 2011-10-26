/* EtherLinkXL.c: A 3Com EtherLink PCI III/XL ethernet driver for linux. */
/*
	Written 1996-2000 by Donald Becker.

	This software may be used and distributed according to the terms of
	the GNU General Public License (GPL), incorporated herein by reference.
	Drivers based on or derived from this code fall under the GPL and must
	retain the authorship, copryight and license notice.  This file is not
	a complete program and may only be used when the entire operating
	system is licensed under the GPL.

	This driver is for the 3Com "Vortex" and "Boomerang" series ethercards.
	Members of the series include Fast EtherLink 3c590/3c592/3c595/3c597
	and the EtherLink XL 3c900 and 3c905 cards.

	The original author may be reached as becker@scyld.com, or C/O
	Scyld Computing Corporation
	410 Severn Ave., Suite 210
	Annapolis MD 21403

	Support information and updates are available at
	http://www.scyld.com/network/vortex.html
*/

static const char versionA[] =
"3c59x.c:v0.99Q 5/16/2000 Donald Becker, becker@scyld.com\n";
static const char versionB[] =
"  http://www.scyld.com/network/vortex.html\n";

/* The user-configurable values.
   These may be modified when a driver module is loaded.*/

static int debug = 1;			/* 1 normal messages, 0 quiet .. 7 verbose. */
#define vortex_debug debug

/* This driver uses 'options' to pass the media type, full-duplex flag, etc.
   See media_tbl[] and the web page for the possible types.
   There is no limit on card count, MAX_UNITS limits only module options. */
#define MAX_UNITS 8
static int options[MAX_UNITS] = { -1, -1, -1, -1, -1, -1, -1, -1,};
static int full_duplex[MAX_UNITS] = {-1, -1, -1, -1, -1, -1, -1, -1};

/* Maximum events (Rx packets, etc.) to handle at each interrupt. */
static int max_interrupt_work = 32;

/* Set the copy breakpoint for the copy-only-tiny-frames scheme.
   Setting to > 1512 effectively disables this feature. */
static const int rx_copybreak = 200;
/* Allow setting MTU to a larger size, bypassing the normal Ethernet setup. */
static const int mtu = 1500;

/* Use hardware checksums? */
static int use_hw_csums = 1;

/* For Cyclone,Tornado cards, polling interval for DownListPtr */
static int down_poll_rate = 20;

/* Autodetect link polarity reversal? */
static int auto_polarity = 1;

/* Operational parameters that are set at compile time. */

/* Keep the ring sizes a power of two for compile efficiency.
   The compiler will convert <unsigned>'%'<2^N> into a bit mask.
   Making the Tx ring too large decreases the effectiveness of channel
   bonding and packet priority.
   There are no ill effects from too-large receive rings. */
#define TX_RING_SIZE	16
#define TX_QUEUE_LEN	10		/* Limit ring entries actually used.  */
#define RX_RING_SIZE	32

/* Operational parameters that usually are not changed. */
/* Time in jiffies before concluding the transmitter is hung. */
#define TX_TIMEOUT  (2*HZ)

#define PKT_BUF_SZ		1536			/* Size of each temporary Rx buffer.*/

#if !defined(__OPTIMIZE__)
#warning  You must compile this file with the correct options!
#warning  See the last lines of the source file.
#error You must compile this driver with "-O".
#endif

#include <linux/config.h>
#include <linux/version.h>
#ifdef MODULE
#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif
#include <linux/module.h>
#else
#define MOD_INC_USE_COUNT
#define MOD_DEC_USE_COUNT
#endif

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/malloc.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <asm/irq.h>
#include <asm/byteorder.h>
#include <asm/bitops.h>
#include <asm/io.h>

/* Kernel compatibility defines, some common to David Hinds' PCMCIA package.
   This is only in the support-all-kernels source code. */

#if (LINUX_VERSION_CODE <= 0x20100)
#ifndef __alpha__
#define ioremap(a,b) \
	(((a)<0x100000) ? (void *)((u_long)(a)) : vremap(a,b))
#define iounmap(v) \
	do { if ((u_long)(v) > 0x100000) vfree(v); } while (0)
#endif
#endif
#if LINUX_VERSION_CODE < 0x20138
#define test_and_set_bit(val, addr) set_bit(val, addr)
typedef long spinlock_t;
#define SPIN_LOCK_UNLOCKED 0
#define spin_lock(lock)
#define spin_unlock(lock)
#define spin_lock_irqsave(lock, flags)	save_flags(flags); cli();
#define spin_unlock_irqrestore(lock, flags) restore_flags(flags);
#endif
#if LINUX_VERSION_CODE < 0x20155
#define PCI_SUPPORT_VER1
#else
#define PCI_SUPPORT_VER2
#endif
#if LINUX_VERSION_CODE < 0x20159
#define dev_free_skb(skb) dev_kfree_skb (skb, FREE_WRITE);
#else  /* Grrr, incompatible changes should change the name. */
#define dev_free_skb(skb) dev_kfree_skb(skb);
#endif
#if ! defined(CAP_NET_ADMIN)
#define capable(CAP_XXX) (suser())
#endif

#define virt_to_le32desc(addr)  cpu_to_le32(virt_to_bus(addr))
#define le32desc_to_virt(addr)  bus_to_virt(le32_to_cpu(addr))

MODULE_AUTHOR("Donald Becker <becker@scyld.com>");
MODULE_DESCRIPTION("3Com EtherLink XL (3c590/3c900 series) driver");
MODULE_PARM(debug, "i");
MODULE_PARM(options, "1-" __MODULE_STRING(MAX_UNITS) "i");
MODULE_PARM(full_duplex, "1-" __MODULE_STRING(MAX_UNITS) "i");
MODULE_PARM(rx_copybreak, "i");
MODULE_PARM(max_interrupt_work, "i");
MODULE_PARM(use_hw_csums, "i");
MODULE_PARM(down_poll_rate, "i");

/* Operational parameter that usually are not changed. */

/* Set iff a MII transceiver on any interface requires mdio preamble.
   This only set with the original DP83840 on older 3c905 boards, so the extra
   code size of a per-interface flag is not worthwhile. */
static char mii_preamble_required = 0;

/* Performance and path-coverage information. */
static int rx_nocopy = 0, rx_copy = 0, queued_packet = 0, rx_csumhits;

/*
				Theory of Operation

I. Board Compatibility

This device driver is designed for the 3Com FastEtherLink and FastEtherLink
XL, 3Com's PCI to 10/100baseT adapters.  It also works with the 10Mbs
versions of the FastEtherLink cards.  The supported product IDs are
in the pci_tbl[] list.

The related ISA 3c515 is supported with a separate driver, 3c515.c, included
with the kernel source.

II. Board-specific settings

PCI bus devices are configured by the system at boot time, so no jumpers
need to be set on the board.  The system BIOS should be set to assign the
PCI INTA signal to an otherwise unused system IRQ line.

The EEPROM settings for media type and forced-full-duplex are observed.
The EEPROM media type should be left at the default "autoselect" unless using
10base2 or AUI connections which cannot be reliably detected.

III. Driver operation

The 3c59x series use an interface that's very similar to the previous 3c5x9
series.  The primary interface is two programmed-I/O FIFOs, with an
alternate single-contiguous-region bus-master transfer (see next).

The 3c900 "Boomerang" series uses a full-bus-master interface with separate
lists of transmit and receive descriptors, similar to the AMD LANCE/PCnet,
DEC Tulip and Intel Speedo3.  The first chip version retains a compatible
programmed-I/O interface that has been removed in 'B' and subsequent board
revisions.

One extension that is advertised in a very large font is that the adapters
are capable of being bus masters.  On the Vortex chip this capability was
only for a single contiguous region making it far less useful than the full
bus master capability.  There is a significant performance impact of taking
an extra interrupt or polling for the completion of each transfer, as well
as difficulty sharing the single transfer engine between the transmit and
receive threads.  Using DMA transfers is a win only with large blocks or
with the flawed versions of the Intel Orion motherboard PCI controller.

The Boomerang chip's full-bus-master interface is useful, and has the
currently-unused advantages over other similar chips that queued transmit
packets may be reordered and receive buffer groups are associated with a
single frame.

With full-bus-master support, this driver uses a "RX_COPYBREAK" scheme.
Rather than a fixed intermediate receive buffer, this scheme allocates
full-sized skbuffs as receive buffers.  The value RX_COPYBREAK is used as
the copying breakpoint: it is chosen to trade-off the memory wasted by
passing the full-sized skbuff to the queue layer for all frames vs. the
copying cost of copying a frame to a correctly-sized skbuff.


IIIC. Synchronization
The driver runs as two independent, single-threaded flows of control.  One
is the send-packet routine, which enforces single threaded by the tx queue
system.  The other thread is the interrupt handler, which is single
threaded by the hardware and other software.

IV. Notes

Thanks to Cameron Spitzer and Terry Murphy of 3Com for providing development
3c590, 3c595, and 3c900 boards.
The name "Vortex" is the internal 3Com project name for the PCI ASIC, and
the EISA version is called "Demon".  According to Terry these names come
from rides at the local amusement park.

The new chips support both ethernet (1.5K) and FDDI (4.5K) packet sizes.
This driver only supports ethernet packets on some kernels because of the
skbuff allocation limit of 4K.
*/

/* This table drives the PCI probe routines.  It's mostly boilerplate in all
   of the drivers, and will likely be provided by some future kernel.
*/
enum pci_flags_bit {
	PCI_USES_IO=1, PCI_USES_MEM=2, PCI_USES_MASTER=4,
	PCI_ADDR0=0x10<<0, PCI_ADDR1=0x10<<1, PCI_ADDR2=0x10<<2, PCI_ADDR3=0x10<<3,
};
struct pci_id_info {
	const char *name;
	u16	vendor_id, device_id, device_id_mask, flags;
	int drv_flags, io_size;
	struct net_device *(*probe1)(int pci_bus, int pci_devfn, struct net_device *dev,
							 long ioaddr, int irq, int chip_idx, int fnd_cnt);
};

/* The Vortex size is twice that of the original EtherLinkIII series: the
   runtime register window, window 1, is now always mapped in.
   The Boomerang size is twice as large as the Vortex -- it has additional
   bus master control registers. */
#define VORTEX_SIZE 0x20
#define BOOMERANG_SIZE 0x40
#define CYCLONE_SIZE 0x80
enum { IS_VORTEX=1, IS_BOOMERANG=2, IS_CYCLONE=4, IS_TORNADO=8,
	   HAS_PWR_CTRL=0x10, HAS_MII=0x20, HAS_NWAY=0x40, HAS_CB_FNS=0x80,
	   EEPROM_8BIT=0x200, INVERT_LED_PWR=0x400, MII_XCVR_PWR=0x800,
	   HAS_FIFO_BUG=0x1000, };
static struct net_device *vortex_probe1(int pci_bus, int pci_devfn,
									struct net_device *dev, long ioaddr,
									int irq, int dev_id, int card_idx);
static struct pci_id_info pci_tbl[] = {
	{"3c575 Boomerang CardBus",		0x10B7, 0x5057, 0xffff,
	 PCI_USES_IO|PCI_USES_MASTER, IS_BOOMERANG|HAS_MII|EEPROM_8BIT,
	 64, vortex_probe1},
	{"3CCFE575BT Cyclone CardBus",	0x10B7, 0x5157, 0xffff,
	 PCI_USES_IO|PCI_USES_MASTER, IS_CYCLONE|HAS_NWAY|HAS_CB_FNS|
	 EEPROM_8BIT|INVERT_LED_PWR, 128, vortex_probe1},
	{"3CCFE575CT Tornado CardBus",	0x10B7, 0x5257, 0xffff,
	 PCI_USES_IO|PCI_USES_MASTER, IS_TORNADO|HAS_NWAY|HAS_CB_FNS|
	 EEPROM_8BIT|MII_XCVR_PWR, 128, vortex_probe1},
	{"3CCFE656 Cyclone CardBus",	0x10B7, 0x6560, 0xffff,
	 PCI_USES_IO|PCI_USES_MASTER, IS_CYCLONE|HAS_NWAY|HAS_CB_FNS|
	 EEPROM_8BIT|INVERT_LED_PWR|MII_XCVR_PWR, 128, vortex_probe1},
	{"3CCFEM656B Cyclone CardBus",	0x10B7, 0x6562, 0xffff,
	 PCI_USES_IO|PCI_USES_MASTER, IS_CYCLONE|HAS_NWAY|HAS_CB_FNS|
	 EEPROM_8BIT|INVERT_LED_PWR|MII_XCVR_PWR, 128, vortex_probe1},
	{"3CXFEM656C Tornado CardBus",	0x10B7, 0x6564, 0xffff,
	 PCI_USES_IO|PCI_USES_MASTER, IS_TORNADO|HAS_NWAY|HAS_CB_FNS|
	 EEPROM_8BIT|MII_XCVR_PWR, 128, vortex_probe1},
	{"3c575 series CardBus (unknown version)", 0x10B7, 0x5057, 0xf0ff,
	 PCI_USES_IO|PCI_USES_MASTER, IS_BOOMERANG|HAS_MII|
	 EEPROM_8BIT|INVERT_LED_PWR, 64, vortex_probe1},
	{0,},						/* 0 terminated list. */
};

/* Operational definitions.
   These are not used by other compilation units and thus are not
   exported in a ".h" file.

   First the windows.  There are eight register windows, with the command
   and status registers available in each.
   */
#define EL3WINDOW(win_num) outw(SelectWindow + (win_num), ioaddr + EL3_CMD)
#define EL3_CMD 0x0e
#define EL3_STATUS 0x0e

/* The top five bits written to EL3_CMD are a command, the lower
   11 bits are the parameter, if applicable.
   Note that 11 parameters bits was fine for ethernet, but the new chip
   can handle FDDI length frames (~4500 octets) and now parameters count
   32-bit 'Dwords' rather than octets. */

enum vortex_cmd {
	TotalReset = 0<<11, SelectWindow = 1<<11, StartCoax = 2<<11,
	RxDisable = 3<<11, RxEnable = 4<<11, RxReset = 5<<11,
	UpStall = 6<<11, UpUnstall = (6<<11)+1,
	DownStall = (6<<11)+2, DownUnstall = (6<<11)+3,
	RxDiscard = 8<<11, TxEnable = 9<<11, TxDisable = 10<<11, TxReset = 11<<11,
	FakeIntr = 12<<11, AckIntr = 13<<11, SetIntrEnb = 14<<11,
	SetStatusEnb = 15<<11, SetRxFilter = 16<<11, SetRxThreshold = 17<<11,
	SetTxThreshold = 18<<11, SetTxStart = 19<<11,
	StartDMAUp = 20<<11, StartDMADown = (20<<11)+1, StatsEnable = 21<<11,
	StatsDisable = 22<<11, StopCoax = 23<<11, SetTxReclaim = 24<<11,
	SetFilterBit = 25<<11,};

/* The SetRxFilter command accepts the following classes: */
enum RxFilter {
	RxStation = 1, RxMulticast = 2, RxBroadcast = 4, RxProm = 8 };

/* Bits in the general status register. */
enum vortex_status {
	IntLatch = 0x0001, HostError = 0x0002, TxComplete = 0x0004,
	TxAvailable = 0x0008, RxComplete = 0x0010, RxEarly = 0x0020,
	IntReq = 0x0040, StatsFull = 0x0080,
	DMADone = 1<<8, DownComplete = 1<<9, UpComplete = 1<<10,
	DMAInProgress = 1<<11,			/* DMA controller is still busy.*/
	CmdInProgress = 1<<12,			/* EL3_CMD is still busy.*/
};

/* Register window 1 offsets, the window used in normal operation.
   On the Vortex this window is always mapped at offsets 0x10-0x1f. */
enum Window1 {
	TX_FIFO = 0x10,  RX_FIFO = 0x10,  RxErrors = 0x14,
	RxStatus = 0x18,  Timer=0x1A, TxStatus = 0x1B,
	TxFree = 0x1C, /* Remaining free bytes in Tx buffer. */
};
enum Window0 {
	Wn0EepromCmd = 10,		/* Window 0: EEPROM command register. */
	Wn0EepromData = 12,		/* Window 0: EEPROM results register. */
	IntrStatus=0x0E,		/* Valid in all windows. */
};
enum Win0_EEPROM_bits {
	EEPROM_Read = 0x80, EEPROM_WRITE = 0x40, EEPROM_ERASE = 0xC0,
	EEPROM_EWENB = 0x30,		/* Enable erasing/writing for 10 msec. */
	EEPROM_EWDIS = 0x00,		/* Disable EWENB before 10 msec timeout. */
};
/* EEPROM locations. */
enum eeprom_offset {
	PhysAddr01=0, PhysAddr23=1, PhysAddr45=2, ModelID=3,
	EtherLink3ID=7, IFXcvrIO=8, IRQLine=9,
	NodeAddr01=10, NodeAddr23=11, NodeAddr45=12,
	DriverTune=13, Checksum=15};

enum Window2 {			/* Window 2. */
	Wn2_ResetOptions=12,
};
enum Window3 {			/* Window 3: MAC/config bits. */
	Wn3_Config=0, Wn3_MAC_Ctrl=6, Wn3_Options=8,
};
union wn3_config {
	int i;
	struct w3_config_fields {
		unsigned int ram_size:3, ram_width:1, ram_speed:2, rom_size:2;
		int pad8:8;
		unsigned int ram_split:2, pad18:2, xcvr:4, autoselect:1;
		int pad24:7;
	} u;
};

enum Window4 {		/* Window 4: Xcvr/media bits. */
	Wn4_FIFODiag = 4, Wn4_NetDiag = 6, Wn4_PhysicalMgmt=8, Wn4_Media = 10,
};
enum Win4_Media_bits {
	Media_SQE = 0x0008,		/* Enable SQE error counting for AUI. */
	Media_10TP = 0x00C0,	/* Enable link beat and jabber for 10baseT. */
	Media_Lnk = 0x0080,		/* Enable just link beat for 100TX/100FX. */
	Media_LnkBeat = 0x0800,
};
enum Window7 {					/* Window 7: Bus Master control. */
	Wn7_MasterAddr = 0, Wn7_MasterLen = 6, Wn7_MasterStatus = 12,
};
/* Boomerang bus master control registers. */
enum MasterCtrl {
	PktStatus = 0x20, DownListPtr = 0x24, FragAddr = 0x28, FragLen = 0x2c,
	DownBurstThresh=0x2a, DownPollRate = 0x2d, TxFreeThreshold = 0x2f,
	UpPktStatus = 0x30, UpListPtr = 0x38,
};

/* The Rx and Tx descriptor lists.
   Caution Alpha hackers: these types are 32 bits!  Note also the 8 byte
   alignment contraint on tx_ring[] and rx_ring[]. */
#define LAST_FRAG  0x80000000			/* Last Addr/Len pair in descriptor. */
struct boom_rx_desc {
	u32 next;					/* Last entry points to 0.   */
	s32 status;
	u32 addr;					/* Up to 63 addr/len pairs possible. */
	s32 length;					/* Set LAST_FRAG to indicate last pair. */
};
/* Values for the Rx status entry. */
enum rx_desc_status {
	RxDComplete=0x00008000, RxDError=0x4000,
	/* See boomerang_rx() for actual error bits */
	IPChksumErr=1<<25, TCPChksumErr=1<<26, UDPChksumErr=1<<27,
	IPChksumValid=1<<29, TCPChksumValid=1<<30, UDPChksumValid=1<<31,
};

struct boom_tx_desc {
	u32 next;					/* Last entry points to 0.   */
	s32 status;					/* bits 0:12 length, others see below.  */
	u32 addr;
	s32 length;
};

/* Values for the Tx status entry. */
enum tx_desc_status {
	CRCDisable=0x2000, TxDComplete=0x8000,
	AddIPChksum=0x02000000, AddTCPChksum=0x04000000, AddUDPChksum=0x08000000,
	TxIntrUploaded=0x80000000,		/* IRQ when in FIFO, but maybe not sent. */
};

/* Chip features we care about in vp->capabilities, read from the EEPROM. */
enum ChipCaps { CapBusMaster=0x20, CapPwrMgmt=0x2000 };

#define PRIV_ALIGN	15 	/* Required alignment mask */
struct vortex_private {
	/* The Rx and Tx rings should be quad-word-aligned. */
	struct boom_rx_desc rx_ring[RX_RING_SIZE];
	struct boom_tx_desc tx_ring[TX_RING_SIZE];
	/* The addresses of transmit- and receive-in-place skbuffs. */
	struct sk_buff* rx_skbuff[RX_RING_SIZE];
	struct sk_buff* tx_skbuff[TX_RING_SIZE];
	struct net_device *next_module;
	void *priv_addr;
	/* Keep the Rx and Tx variables grouped on their own cache lines. */
	struct boom_rx_desc *rx_head_desc;
	unsigned int cur_rx, dirty_rx;		/* Producer/consumer ring indices */
	unsigned int rx_buf_sz;				/* Based on MTU+slack. */

	struct boom_tx_desc *tx_desc_tail;
	unsigned int cur_tx, dirty_tx;
	struct sk_buff *tx_skb;		/* Packet being eaten by bus master ctrl.  */

	long last_reset;
	struct net_device_stats stats;
	char *cb_fn_base;			/* CardBus function status addr space. */
	int chip_id, drv_flags;
	u8 pci_bus, pci_devfn;		/* PCI configuration space information. */

	/* The remainder are related to chip state, mostly media selection. */
	struct timer_list timer;	/* Media selection timer. */
	int options;				/* User-settable misc. driver options. */
	unsigned int media_override:4, 			/* Passed-in media type. */
		default_media:4,				/* Read from the EEPROM/Wn3_Config. */
		full_duplex:1, medialock:1, autoselect:1,
		bus_master:1,				/* Vortex can only do a fragment bus-m. */
		full_bus_master_tx:1, full_bus_master_rx:2, /* Boomerang  */
		hw_csums:1,				/* Has hardware checksums. */
		tx_full:1, restart_tx:1,
		open:1, reap:1,
		polling:1;
	u16 status_enable;
	u16 intr_enable;
	u16 available_media;				/* From Wn3_Options. */
	u16 capabilities, info1, info2;		/* Various, from EEPROM. */
	u16 advertising;					/* NWay media advertisement */
	unsigned char phys[2];				/* MII device addresses. */
	u16 deferred_irqs;
	spinlock_t lock;
};

/* The action to take with a media selection timer tick.
   Note that we deviate from the 3Com order by checking 10base2 before AUI.
 */
enum xcvr_types {
	XCVR_10baseT=0, XCVR_AUI, XCVR_10baseTOnly, XCVR_10base2, XCVR_100baseTx,
	XCVR_100baseFx, XCVR_MII=6, XCVR_NWAY=8, XCVR_ExtMII=9, XCVR_Default=10,
};

static struct media_table {
	char *name;
	unsigned int media_bits:16,		/* Bits to set in Wn4_Media register. */
		mask:8,				/* The transceiver-present bit in Wn3_Config.*/
		next:8;				/* The media type to try next. */
	int wait;			/* Time before we check media status. */
} media_tbl[] = {
  {	"10baseT",   Media_10TP,0x08, XCVR_10base2, (14*HZ)/10},
  { "10Mbs AUI", Media_SQE, 0x20, XCVR_Default, (1*HZ)/10},
  { "undefined", 0,			0x80, XCVR_10baseT, 10000},
  { "10base2",   0,			0x10, XCVR_AUI,		(1*HZ)/10},
  { "100baseTX", Media_Lnk, 0x02, XCVR_100baseFx, (14*HZ)/10},
  { "100baseFX", Media_Lnk, 0x04, XCVR_MII,		(14*HZ)/10},
  { "MII",		 0,			0x41, XCVR_10baseT, 3*HZ },
  { "undefined", 0,			0x01, XCVR_10baseT, 10000},
  { "Autonegotiate", 0,		0x41, XCVR_10baseT, 3*HZ},
  { "MII-External",	 0,		0x41, XCVR_10baseT, 3*HZ },
  { "Default",	 0,			0xFF, XCVR_10baseT, 10000},
};

static void vortex_up(struct net_device *dev);
static void vortex_down(struct net_device *dev);
static int vortex_open(struct net_device *dev);
static void set_media_type(struct net_device *dev);
static void activate_xcvr(struct net_device *dev);
static void start_operation(struct net_device *dev);
static void mdio_sync(long ioaddr, int bits);
static int mdio_read(long ioaddr, int phy_id, int location);
static void mdio_write(long ioaddr, int phy_id, int location, int value);
static void vortex_timer(unsigned long arg);
static void vortex_tx_timeout(struct net_device *dev);
static int vortex_start_xmit(struct sk_buff *skb, struct net_device *dev);
static int boomerang_start_xmit(struct sk_buff *skb, struct net_device *dev);
static int vortex_rx(struct net_device *dev);
static int boomerang_rx(struct net_device *dev);
static void vortex_interrupt(int irq, void *dev_id, struct pt_regs *regs);
static int vortex_close(struct net_device *dev);
static void update_stats(long ioaddr, struct net_device *dev);
static struct net_device_stats *vortex_get_stats(struct net_device *dev);
static void set_rx_mode(struct net_device *dev);
static int vortex_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
static void acpi_wake(int pci_bus, int pci_devfn);
static void acpi_set_WOL(struct net_device *dev);


/* A list of all installed Vortex devices, for removing the driver module. */
static struct net_device *root_vortex_dev = NULL;

#include <pcmcia/driver_ops.h>

static void vortex_reap(void)
{
	struct net_device **devp, **next;
	for (devp = &root_vortex_dev; *devp; devp = next) {
		struct vortex_private *vp = (*devp)->priv;
		next = &vp->next_module;
		if (vp->open || !vp->reap) continue;
		unregister_netdev(*devp);
		if (vp->cb_fn_base) iounmap(vp->cb_fn_base);
		kfree(*devp);
		*devp = *next; next = devp;
		kfree(vp->priv_addr);
	}
}

static dev_node_t *vortex_attach(dev_locator_t *loc)
{
	u16 dev_id, vendor_id;
	u32 io;
	u8 bus, devfn, irq;
	struct net_device *dev;
	int chip_idx;

	vortex_reap();
	if (loc->bus != LOC_PCI) return NULL;
	bus = loc->b.pci.bus; devfn = loc->b.pci.devfn;
	pcibios_read_config_dword(bus, devfn, PCI_BASE_ADDRESS_0, &io);
	pcibios_read_config_byte(bus, devfn, PCI_INTERRUPT_LINE, &irq);
	pcibios_read_config_word(bus, devfn, PCI_VENDOR_ID, &vendor_id);
	pcibios_read_config_word(bus, devfn, PCI_DEVICE_ID, &dev_id);
	printk(KERN_INFO "vortex_attach(device %02x:%02x.%d)\n",
		   bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
	io &= ~3;
	if (io == 0 || irq == 0) {
		printk(KERN_ERR "The 3Com CardBus Ethernet interface was not "
			   "assigned an %s.\n" KERN_ERR "  It will not be activated.\n",
			   io == 0 ? "I/O address" : "IRQ");
		return NULL;
	}
	for (chip_idx = 0; pci_tbl[chip_idx].vendor_id; chip_idx++)
		if (vendor_id == pci_tbl[chip_idx].vendor_id
			&& (dev_id & pci_tbl[chip_idx].device_id_mask) ==
			pci_tbl[chip_idx].device_id)
			break;
	if (pci_tbl[chip_idx].vendor_id == 0) { 		/* Compiled out! */
		printk(KERN_INFO "Unable to match chip type %4.4x %4.4x in "
			   "vortex_attach().\n", vendor_id, dev_id);
		return NULL;
	}
	dev = vortex_probe1(bus, devfn, NULL, io, irq, chip_idx, MAX_UNITS+1);
	if (dev) {
		dev_node_t *node = kmalloc(sizeof(dev_node_t), GFP_KERNEL);
		strcpy(node->dev_name, dev->name);
		node->major = node->minor = 0;
		node->next = NULL;
		MOD_INC_USE_COUNT;
		return node;
	}
	return NULL;
}

static void vortex_detach(dev_node_t *node)
{
	struct net_device *dev, *next;
	printk(KERN_DEBUG "vortex_detach(%s)\n", node->dev_name);
	for (dev = root_vortex_dev; dev; dev = next) {
		next = ((struct vortex_private *)dev->priv)->next_module;
		if (strcmp(dev->name, node->dev_name) == 0) break;
	}
	if (dev && dev->priv) {
		struct vortex_private *vp = dev->priv;
		netif_device_detach(dev);
		if (vp->open) vortex_down(dev);
		vp->reap = 1;
		kfree(node);
		MOD_DEC_USE_COUNT;
	}
}

static void vortex_suspend(dev_node_t *node)
{
	struct net_device *dev, *next;
	printk(KERN_DEBUG "vortex_suspend(%s)\n", node->dev_name);
	for (dev = root_vortex_dev; dev; dev = next) {
		next = ((struct vortex_private *)dev->priv)->next_module;
		if (strcmp(dev->name, node->dev_name) == 0) break;
	}
	if (dev && dev->priv) {
		struct vortex_private *vp = (struct vortex_private *)dev->priv;
		netif_device_detach(dev);
		if (vp->open) vortex_down(dev);
	}
}

static void vortex_resume(dev_node_t *node)
{
	struct net_device *dev, *next;
	printk(KERN_DEBUG "vortex_resume(%s)\n", node->dev_name);
	for (dev = root_vortex_dev; dev; dev = next) {
		next = ((struct vortex_private *)dev->priv)->next_module;
		if (strcmp(dev->name, node->dev_name) == 0) break;
	}
	if (dev && dev->priv) {
		struct vortex_private *vp = (struct vortex_private *)dev->priv;
		if (vp->open) vortex_up(dev);
		netif_device_attach(dev);
	}
}

struct driver_operations vortex_ops = {
	"3c575_cb", vortex_attach, vortex_suspend, vortex_resume, vortex_detach
};

int init_module(void)
{
	if (debug)
		printk(KERN_INFO "%s" KERN_INFO "%s", versionA, versionB);
	register_driver(&vortex_ops);
	return 0;
}

static struct net_device *vortex_probe1(int pci_bus, int pci_devfn,
									struct net_device *dev, long ioaddr,
									int irq, int chip_idx, int find_cnt)
{
	struct vortex_private *vp;
	void *priv_mem;
	int option;
	unsigned int eeprom[0x40], checksum = 0;		/* EEPROM contents */
	int drv_flags = pci_tbl[chip_idx].drv_flags;
	int i, step;

	dev = init_etherdev(dev, 0);

	printk(KERN_INFO "%s: 3Com %s at 0x%lx, ",
		   dev->name, pci_tbl[chip_idx].name, ioaddr);

	/* Make certain elements e.g. descriptor lists are aligned. */
	priv_mem = kmalloc(sizeof(*vp) + PRIV_ALIGN, GFP_KERNEL);
	/* Check for the very unlikely case of no memory. */
	if (priv_mem == NULL) {
		printk(" INTERFACE MEMORY ALLOCATION FAILURE.\n");
		return NULL;
	}

	dev->base_addr = ioaddr;
	dev->irq = irq;
	dev->mtu = mtu;

	dev->priv = vp = (void *)(((long)priv_mem + PRIV_ALIGN) & ~PRIV_ALIGN);
	memset(vp, 0, sizeof(*vp));
	vp->priv_addr = priv_mem;

	vp->next_module = root_vortex_dev;
	root_vortex_dev = dev;

	vp->chip_id = chip_idx;
	vp->pci_bus = pci_bus;
	vp->pci_devfn = pci_devfn;
	vp->drv_flags = drv_flags;

	/* The lower four bits are the media type. */
	if (dev->mem_start)
		option = dev->mem_start;
	else if (find_cnt < MAX_UNITS)
		option = options[find_cnt];
	else
		option = -1;

	if (option >= 0) {
		vp->media_override = ((option & 7) == 2)  ?  0  :  option & 15;
		vp->full_duplex = (option & 0x200) ? 1 : 0;
		vp->bus_master = (option & 16) ? 1 : 0;
	} else {
		vp->media_override = 7;
		vp->full_duplex = 0;
		vp->bus_master = 0;
	}
	if (find_cnt < MAX_UNITS  &&  full_duplex[find_cnt] > 0)
		vp->full_duplex = 1;

	if (vp->full_duplex)
		vp->medialock = 1;
	vp->options = option;

	/* Read the station address from the EEPROM. */
	EL3WINDOW(0);
	for (i = 0; i < 0x40; i++) {
		int timer;
		outw((drv_flags & EEPROM_8BIT ? 0x230 : EEPROM_Read) + i,
			 ioaddr + Wn0EepromCmd);
		/* The read may take up to 162 usec, timed with PCI cycles. */
		for (timer = 162*5; timer >= 0; timer--) {
			if ((inw(ioaddr + Wn0EepromCmd) & 0x8000) == 0)
				break;
		}
		eeprom[i] = inw(ioaddr + Wn0EepromData);
	}
	for (i = 0; i < 0x18; i++)
		checksum ^= eeprom[i];
	checksum = (checksum ^ (checksum >> 8)) & 0xff;
	if (checksum != 0x00) {		/* Grrr, needless incompatible change 3Com. */
		while (i < 0x21)
			checksum ^= eeprom[i++];
		checksum = (checksum ^ (checksum >> 8)) & 0xff;
	}
	if (checksum != 0x00  &&  !(drv_flags & IS_TORNADO))
		printk(" ***INVALID CHECKSUM %4.4x*** ", checksum);

	for (i = 0; i < 3; i++)
		((u16 *)dev->dev_addr)[i] = htons(eeprom[i + 10]);
	for (i = 0; i < 6; i++)
		printk("%c%2.2x", i ? ':' : ' ', dev->dev_addr[i]);
	EL3WINDOW(2);
	for (i = 0; i < 6; i++)
		outb(dev->dev_addr[i], ioaddr + i);

#ifdef __sparc__
	printk(", IRQ %s\n", __irq_itoa(dev->irq));
#else
	printk(", IRQ %d\n", dev->irq);
	/* Tell them about an invalid IRQ. */
	if (vortex_debug && (dev->irq <= 0))
		printk(KERN_WARNING " *** Warning: IRQ %d is unlikely to work! ***\n",
			   dev->irq);
#endif
	EL3WINDOW(4);
	step = (inb(ioaddr + Wn4_NetDiag) & 0x1e) >> 1;
	printk(KERN_INFO "  product code '%c%c' rev %02x.%d date %02d-"
		   "%02d-%02d\n", eeprom[6]&0xff, eeprom[6]>>8, eeprom[0x14],
		   step, (eeprom[4]>>5) & 15, eeprom[4] & 31, eeprom[4]>>9);

	if ((eeprom[0x14] == 0x07) && (step == 1))
		vp->drv_flags = drv_flags |= HAS_FIFO_BUG;
	if (drv_flags & HAS_CB_FNS) {
		u32 fn_st_addr;			/* Cardbus function status space */
		pcibios_read_config_dword(pci_bus, pci_devfn, PCI_BASE_ADDRESS_2,
								  &fn_st_addr);
		if (fn_st_addr)
			vp->cb_fn_base = ioremap(fn_st_addr & ~3, 128);
		printk(KERN_INFO "%s: CardBus functions mapped %8.8x->%p.\n",
			   dev->name, fn_st_addr, vp->cb_fn_base);
	}

	/* Extract our information from the EEPROM data. */
	vp->info1 = eeprom[13];
	vp->info2 = eeprom[15];
	vp->capabilities = eeprom[16];

	if (vp->info1 & 0x8000)
		vp->full_duplex = 1;

	/* Turn on the transceiver. */
	activate_xcvr(dev);

	{
		char *ram_split[] = {"5:3", "3:1", "1:1", "3:5"};
		union wn3_config config;
		EL3WINDOW(3);
		vp->available_media = inw(ioaddr + Wn3_Options);
		if ((vp->available_media & 0xff) == 0)		/* Broken 3c916 */
			vp->available_media = 0x40;
		config.i = inl(ioaddr + Wn3_Config);
		if (vortex_debug > 1)
			printk(KERN_DEBUG "  Internal config register is %4.4x, "
				   "transceivers %#x.\n", config.i, inw(ioaddr + Wn3_Options));
		printk(KERN_INFO "  %dK %s-wide RAM %s Rx:Tx split, %s%s interface.\n",
			   8 << config.u.ram_size,
			   config.u.ram_width ? "word" : "byte",
			   ram_split[config.u.ram_split],
			   config.u.autoselect ? "autoselect/" : "",
			   config.u.xcvr > XCVR_ExtMII ? "<invalid transceiver>" :
			   media_tbl[config.u.xcvr].name);
		vp->default_media = config.u.xcvr;
		vp->autoselect = config.u.autoselect;
	}

	if (vp->media_override != 7) {
		printk(KERN_INFO "  Media override to transceiver type %d (%s).\n",
			   vp->media_override, media_tbl[vp->media_override].name);
		dev->if_port = vp->media_override;
	} else
		dev->if_port = vp->default_media;

	if (dev->if_port == XCVR_MII || dev->if_port == XCVR_NWAY) {
		int phy, phy_idx = 0;
		EL3WINDOW(4);
		mii_preamble_required++;
		mii_preamble_required++;
		mdio_read(ioaddr, 24, 1);
		for (phy = 1; phy <= 32 && phy_idx < sizeof(vp->phys); phy++) {
			int mii_status, phyx = phy & 0x1f;
			mii_status = mdio_read(ioaddr, phyx, 1);
			if (mii_status  &&  mii_status != 0xffff) {
				vp->phys[phy_idx++] = phyx;
				printk(KERN_INFO "  MII transceiver found at address %d,"
					   " status %4x.\n", phyx, mii_status);
				if ((mii_status & 0x0040) == 0)
					mii_preamble_required++;
			}
		}
		mii_preamble_required--;
		if (phy_idx == 0) {
			printk(KERN_WARNING"  ***WARNING*** No MII transceivers found!\n");
			vp->phys[0] = 24;
		} else {
			vp->advertising = mdio_read(ioaddr, vp->phys[0], 4);
			if (vp->full_duplex) {
				/* Only advertise the FD media types. */
				vp->advertising &= ~0x02A0;
				mdio_write(ioaddr, vp->phys[0], 4, vp->advertising);
			}
		}
	}

	if (vp->capabilities & CapPwrMgmt)
		acpi_set_WOL(dev);

	if (vp->capabilities & CapBusMaster) {
		vp->full_bus_master_tx = 1;
		printk(KERN_INFO"  Enabling bus-master transmits and %s receives.\n",
			   (vp->info2 & 1) ? "early" : "whole-frame" );
		vp->full_bus_master_rx = (vp->info2 & 1) ? 1 : 2;
	}

	/* We do a request_region() to register /proc/ioports info. */
	request_region(ioaddr, pci_tbl[chip_idx].io_size, dev->name);

	/* The 3c59x-specific entries in the device structure. */
	dev->open = &vortex_open;
	dev->hard_start_xmit = &vortex_start_xmit;
	dev->stop = &vortex_close;
	dev->get_stats = &vortex_get_stats;
	dev->do_ioctl = &vortex_ioctl;
	dev->set_multicast_list = &set_rx_mode;
#ifdef HAVE_TX_TIMEOUT
	dev->tx_timeout = vortex_tx_timeout;
	dev->watchdog_timeo = TX_TIMEOUT;
#endif

	return dev;
}

static void wait_for_completion(struct net_device *dev, int cmd)
{
	int i = 2000;
	outw(cmd, dev->base_addr + EL3_CMD);
	while (--i > 0)
		if (!(inw(dev->base_addr + EL3_STATUS) & CmdInProgress))
			break;
	if (i == 0)
		printk(KERN_NOTICE "%s: command 0x%04x did not complete!\n",
			   dev->name, cmd);
}


static void
vortex_up(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int i;

	acpi_wake(vp->pci_bus, vp->pci_devfn);

	vp->lock = SPIN_LOCK_UNLOCKED;
	activate_xcvr(dev);

	/* Before initializing select the active media port. */
	if (vp->media_override != 7) {
		if (vortex_debug > 1)
			printk(KERN_INFO "%s: Media override to transceiver %d (%s).\n",
				   dev->name, vp->media_override,
				   media_tbl[vp->media_override].name);
		dev->if_port = vp->media_override;
	} else if (vp->autoselect) {
		if (vp->drv_flags & HAS_NWAY)
			dev->if_port = XCVR_NWAY;
		else {
			/* Find first available media type, starting with 100baseTx. */
			dev->if_port = XCVR_100baseTx;
			while (! (vp->available_media & media_tbl[dev->if_port].mask))
				dev->if_port = media_tbl[dev->if_port].next;
		}
	} else
		dev->if_port = vp->default_media;

	if (! vp->medialock)
		vp->full_duplex = 0;

	vp->status_enable = SetStatusEnb | HostError|IntReq|StatsFull|TxComplete|
		(vp->full_bus_master_tx ? DownComplete : TxAvailable) |
		(vp->full_bus_master_rx ? UpComplete : RxComplete) |
		(vp->bus_master ? DMADone : 0);
	vp->intr_enable = SetIntrEnb | IntLatch | TxAvailable | RxComplete |
		StatsFull | HostError | TxComplete | IntReq
		| (vp->bus_master ? DMADone : 0) | UpComplete | DownComplete;

	if (vortex_debug > 1)
		printk(KERN_DEBUG "%s: Initial media type %s %s-duplex.\n",
			   dev->name, media_tbl[dev->if_port].name,
			   vp->full_duplex ? "full":"half");

	set_media_type(dev);
	start_operation(dev);

	spin_lock(&vp->lock);

	if (vortex_debug > 1) {
		EL3WINDOW(4);
		printk(KERN_DEBUG "%s: vortex_open() irq %d media status %4.4x.\n",
			   dev->name, dev->irq, inw(ioaddr + Wn4_Media));
	}

	/* Switch to the stats window, and clear all stats by reading. */
	outw(StatsDisable, ioaddr + EL3_CMD);
	EL3WINDOW(6);
	for (i = 0; i < 10; i++)
		inb(ioaddr + i);
	inw(ioaddr + 10);
	inw(ioaddr + 12);
	/* New: On the Vortex we must also clear the BadSSD counter. */
	EL3WINDOW(4);
	inb(ioaddr + 12);
	/* ..and on the Boomerang we enable the extra statistics bits. */
	outw(0x0040, ioaddr + Wn4_NetDiag);

	/* Switch to register set 7 for normal use. */
	EL3WINDOW(7);
	spin_unlock(&vp->lock);

	vp->tx_full = 0;
	if (vp->full_bus_master_rx) { /* Boomerang bus master. */
		vp->cur_rx = vp->dirty_rx = 0;
		/* Initialize the RxEarly register as recommended. */
		outw(SetRxThreshold + (1536>>2), ioaddr + EL3_CMD);
		outl(0x0020, ioaddr + PktStatus);
		for (i = 0; i < RX_RING_SIZE; i++)
			vp->rx_ring[i].status = 0;
		vp->rx_head_desc = &vp->rx_ring[0];
		outl(virt_to_bus(vp->rx_head_desc), ioaddr + UpListPtr);
	}
	if (vp->full_bus_master_tx) { 		/* Boomerang bus master Tx. */
		vp->cur_tx = vp->dirty_tx = 0;
		vp->tx_desc_tail = &vp->tx_ring[TX_RING_SIZE - 1];
		if ((vp->drv_flags & IS_BOOMERANG) || !down_poll_rate) {
			/* Room for a packet, to avoid long DownStall delays. */
			outb(PKT_BUF_SZ>>8, ioaddr + TxFreeThreshold);
		} else
			outb(down_poll_rate, ioaddr + DownPollRate);

		/* Clear the Tx ring. */
		for (i = 0; i < TX_RING_SIZE; i++)
			vp->tx_skbuff[i] = 0;
		outl(0, ioaddr + DownListPtr);
		vp->restart_tx = 1;
	}
	/* Set receiver mode: presumably accept b-cast and phys addr only. */
	set_rx_mode(dev);
	outw(StatsEnable, ioaddr + EL3_CMD); /* Turn on statistics. */
	if (vp->drv_flags & HAS_FIFO_BUG) /* max out the tx fifo threshold */
		outb(0x1f, ioaddr + DownBurstThresh);

	outw(RxEnable, ioaddr + EL3_CMD); /* Enable the receiver. */
	outw(TxEnable, ioaddr + EL3_CMD); /* Enable transmitter. */
	/* Allow status bits to be seen. */
	outw(vp->status_enable, ioaddr + EL3_CMD);
	/* Ack all pending events, and set active indicator mask. */
	outw(AckIntr | IntLatch | TxAvailable | RxEarly | IntReq,
		 ioaddr + EL3_CMD);
	outw(vp->intr_enable, ioaddr + EL3_CMD);
	if (vp->cb_fn_base)			/* The PCMCIA people are idiots.  */
		writel(0x8000, vp->cb_fn_base + 4);

	init_timer(&vp->timer);
	vp->timer.expires = jiffies + media_tbl[dev->if_port].wait;
	vp->timer.data = (unsigned long)dev;
	vp->timer.function = &vortex_timer;		/* timer handler */
	add_timer(&vp->timer);
}

static void set_media_type(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	union wn3_config config;

	EL3WINDOW(3);
	config.i = inl(ioaddr + Wn3_Config);
	config.u.xcvr = dev->if_port;
	if ( ! (vp->drv_flags & HAS_NWAY))
		outl(config.i, ioaddr + Wn3_Config);

	if (dev->if_port == XCVR_MII || dev->if_port == XCVR_NWAY) {
		int mii_reg1, mii_reg5;
		EL3WINDOW(4);
		/* Read BMSR (reg1) only to clear old status. */
		mii_reg1 = mdio_read(ioaddr, vp->phys[0], 1);
		mii_reg5 = mdio_read(ioaddr, vp->phys[0], 5);
		if (mii_reg5 == 0xffff  ||  mii_reg5 == 0x0000)
			;					/* No MII device or no link partner report */
		else if ((mii_reg5 & 0x0100) != 0	/* 100baseTx-FD */
				 || (mii_reg5 & 0x00C0) == 0x0040) /* 10T-FD, but not 100-HD */
			vp->full_duplex = 1;
		if (vortex_debug > 1)
			printk(KERN_INFO "%s: MII #%d status %4.4x, link partner capability %4.4x,"
				   " setting %s-duplex.\n", dev->name, vp->phys[0],
				   mii_reg1, mii_reg5, vp->full_duplex ? "full" : "half");
		if (!auto_polarity) {
			/* works for TDK 78Q2120 series MII's */
			int i = mdio_read(ioaddr, vp->phys[0], 16) | 0x20;
			mdio_write(ioaddr, vp->phys[0], 16, i);
		}
	}
	if (dev->if_port == XCVR_10base2)
		/* Start the thinnet transceiver. We should really wait 50ms...*/
		outw(StartCoax, ioaddr + EL3_CMD);
	if (dev->if_port != XCVR_NWAY) {
		EL3WINDOW(4);
		outw((inw(ioaddr + Wn4_Media) & ~(Media_10TP|Media_SQE)) |
			 media_tbl[dev->if_port].media_bits, ioaddr + Wn4_Media);
	}

	/* Set the full-duplex bit. */
	EL3WINDOW(3);
	outb(((vp->info1 & 0x8000) || vp->full_duplex ? 0x20 : 0) |
		 (dev->mtu > 1500 ? 0x40 : 0), ioaddr + Wn3_MAC_Ctrl);
}

static void activate_xcvr(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int reset_opts;

	/* Correct some magic bits. */
	EL3WINDOW(2);
	reset_opts = inw(ioaddr + Wn2_ResetOptions);
	if (vp->drv_flags & INVERT_LED_PWR)
		reset_opts |= 0x0010;
	if (vp->drv_flags & MII_XCVR_PWR)
		reset_opts |= 0x4000;
	outw(reset_opts, ioaddr + Wn2_ResetOptions);
}

static void start_operation(struct net_device *dev)
{
	long ioaddr = dev->base_addr;
	int i;

	wait_for_completion(dev, TxReset);
	wait_for_completion(dev, RxReset);
	outw(SetStatusEnb | 0x00, ioaddr + EL3_CMD);
	/* Reset the station address and mask. */
	EL3WINDOW(2);
	for (i = 0; i < 6; i++)
		outb(dev->dev_addr[i], ioaddr + i);
	for (; i < 12; i+=2)
		outw(0, ioaddr + i);
}

static int
vortex_open(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	int i;

#ifdef CARDBUS
	if (vp->reap)
		return -ENODEV;
#endif
	/* Use the now-standard shared IRQ implementation. */
	if (request_irq(dev->irq, &vortex_interrupt, SA_SHIRQ, dev->name, dev)) {
		return -EAGAIN;
	}

	if (vp->full_bus_master_rx) { /* Boomerang bus master. */
		if (vortex_debug > 2)
			printk(KERN_DEBUG "%s:  Filling in the Rx ring.\n", dev->name);
		vp->rx_buf_sz = (dev->mtu <= 1500 ? PKT_BUF_SZ : dev->mtu + 32);
		for (i = 0; i < RX_RING_SIZE; i++) {
			struct sk_buff *skb;
			vp->rx_ring[i].length = cpu_to_le32(vp->rx_buf_sz | LAST_FRAG);
			vp->rx_ring[i].next = virt_to_le32desc(&vp->rx_ring[i+1]);
			skb = dev_alloc_skb(vp->rx_buf_sz);
			vp->rx_skbuff[i] = skb;
			if (skb == NULL)
				break;			/* Bad news!  */
			skb->dev = dev;			/* Mark as being used by this device. */
			skb_reserve(skb, 2);	/* Align IP on 16 byte boundaries */
			vp->rx_ring[i].addr = virt_to_le32desc(skb->tail);
		}
		/* Wrap the ring. */
		vp->rx_ring[i-1].next = virt_to_le32desc(&vp->rx_ring[0]);
	}
	if (vp->full_bus_master_tx)
		dev->hard_start_xmit = &boomerang_start_xmit;

	vortex_up(dev);
	vp->open = 1;
	netif_start_queue(dev);
	netif_mark_up(dev);
	MOD_INC_USE_COUNT;

	return 0;
}

static void vortex_timer(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int next_tick = 60*HZ;
	int ok = 0;
	int media_status, mii_status, old_window;
	unsigned long flags;

	if (vortex_debug > 1)
		printk(KERN_DEBUG "%s: Media selection timer tick happened, %s.\n",
			   dev->name, media_tbl[dev->if_port].name);

	/* This only works with bus-master (non-3c590) chips. */
	if (vp->cur_tx - vp->dirty_tx > 1  &&
		(jiffies - dev->trans_start) > TX_TIMEOUT) {
		/* Check for blocked interrupts. */
		if (inw(ioaddr + EL3_STATUS) & IntLatch) {
			/* We have a blocked IRQ line.  This should never happen, but
			   we recover as best we can.*/
			if ( ! vp->polling) {
				if (jiffies - vp->last_reset > 10*HZ) {
					printk(KERN_ERR "%s: IRQ %d is physically blocked! "
						   "Failing back to low-rate polling.\n",
						   dev->name, dev->irq);
					vp->last_reset = jiffies;
				}
				vp->polling = 1;
			}
			vortex_interrupt(dev->irq, dev, 0);
			next_tick = jiffies + 2;
		} else {
			vortex_tx_timeout(dev);
			vp->last_reset = jiffies;
		}
	}

	disable_irq(dev->irq);
	old_window = inw(ioaddr + EL3_CMD) >> 13;
	EL3WINDOW(4);
	media_status = inw(ioaddr + Wn4_Media);
	switch (dev->if_port) {
	case XCVR_10baseT:  case XCVR_100baseTx:  case XCVR_100baseFx:
		if (media_status & Media_LnkBeat) {
			ok = 1;
			if (vortex_debug > 1)
				printk(KERN_DEBUG "%s: Media %s has link beat, %x.\n",
					   dev->name, media_tbl[dev->if_port].name, media_status);
		} else if (vortex_debug > 1)
			printk(KERN_DEBUG "%s: Media %s has no link beat, %x.\n",
				   dev->name, media_tbl[dev->if_port].name, media_status);
		break;
	case XCVR_MII: case XCVR_NWAY:
		spin_lock_irqsave(&vp->lock, flags);
		mii_status = mdio_read(ioaddr, vp->phys[0], 1);
		ok = 1;
		if (debug > 1)
			printk(KERN_DEBUG "%s: MII transceiver has status %4.4x.\n",
				   dev->name, mii_status);
		if (mii_status & 0x0004) {
			int mii_reg5 = mdio_read(ioaddr, vp->phys[0], 5);
			if (! vp->medialock  &&  mii_reg5 != 0xffff) {
				int duplex = (mii_reg5&0x0100) ||
					(mii_reg5 & 0x01C0) == 0x0040;
				if (vp->full_duplex != duplex) {
					vp->full_duplex = duplex;
					printk(KERN_INFO "%s: Setting %s-duplex based on MII "
						   "#%d link partner capability of %4.4x.\n",
						   dev->name, vp->full_duplex ? "full" : "half",
						   vp->phys[0], mii_reg5);
					/* Set the full-duplex bit. */
					EL3WINDOW(3);
					outb((vp->full_duplex ? 0x20 : 0) |
						 (dev->mtu > 1500 ? 0x40 : 0),
						 ioaddr + Wn3_MAC_Ctrl);
				}
				next_tick = 60*HZ;
			}
		}
		spin_unlock_irqrestore(&vp->lock, flags);
		break;
	default:					/* Other media types handled by Tx timeouts. */
		if (vortex_debug > 1)
			printk(KERN_DEBUG "%s: Media %s has no indication, %x.\n",
				   dev->name, media_tbl[dev->if_port].name, media_status);
		ok = 1;
	}
	if ( ! ok) {
		union wn3_config config;

		do {
			dev->if_port = media_tbl[dev->if_port].next;
		} while ( ! (vp->available_media & media_tbl[dev->if_port].mask));
		if (dev->if_port == XCVR_Default) { /* Go back to default. */
		  dev->if_port = vp->default_media;
		  if (vortex_debug > 1)
			printk(KERN_DEBUG "%s: Media selection failing, using default "
				   "%s port.\n",
				   dev->name, media_tbl[dev->if_port].name);
		} else {
			if (vortex_debug > 1)
				printk(KERN_DEBUG "%s: Media selection failed, now trying "
					   "%s port.\n",
					   dev->name, media_tbl[dev->if_port].name);
			next_tick = media_tbl[dev->if_port].wait;
		}
		outw((media_status & ~(Media_10TP|Media_SQE)) |
			 media_tbl[dev->if_port].media_bits, ioaddr + Wn4_Media);

		EL3WINDOW(3);
		config.i = inl(ioaddr + Wn3_Config);
		config.u.xcvr = dev->if_port;
		outl(config.i, ioaddr + Wn3_Config);

		outw(dev->if_port == XCVR_10base2 ? StartCoax : StopCoax,
			 ioaddr + EL3_CMD);
	}
	EL3WINDOW(old_window);
	enable_irq(dev->irq);

	if (vortex_debug > 2)
	  printk(KERN_DEBUG "%s: Media selection timer finished, %s.\n",
			 dev->name, media_tbl[dev->if_port].name);

	vp->timer.expires = jiffies + next_tick;
	add_timer(&vp->timer);
	if (vp->deferred_irqs)
		outw(FakeIntr, ioaddr + EL3_CMD);
	return;
}

static void vortex_tx_timeout(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;

	printk(KERN_ERR "%s: transmit timed out, tx_status %2.2x status %4.4x.\n",
		   dev->name, inb(ioaddr + TxStatus), inw(ioaddr + EL3_STATUS));
	EL3WINDOW(4);
	printk(KERN_ERR "  diagnostics: net %04x media %04x dma %8.8x.\n",
		   inw(ioaddr + Wn4_NetDiag), inw(ioaddr + Wn4_Media),
		   inl(ioaddr + PktStatus));
	/* Slight code bloat to be user friendly. */
	if ((inb(ioaddr + TxStatus) & 0x88) == 0x88)
		printk(KERN_ERR "%s: Transmitter encountered 16 collisions --"
			   " network cable problem?\n", dev->name);
	if (inw(ioaddr + EL3_STATUS) & IntLatch) {
		printk(KERN_ERR "%s: Interrupt posted but not delivered --"
			   " IRQ blocked by another device?\n", dev->name);
	}

#if ! defined(final_version)
	if (vp->full_bus_master_tx) {
		int i;
		printk(KERN_DEBUG "  Flags; bus-master %d, full %d; dirty %d "
			   "current %d.\n", vp->full_bus_master_tx, vp->tx_full,
			   vp->dirty_tx % TX_RING_SIZE, vp->cur_tx % TX_RING_SIZE);
		printk(KERN_DEBUG "  Transmit list %8.8x vs. %p.\n",
			   inl(ioaddr + DownListPtr),
			   &vp->tx_ring[vp->dirty_tx % TX_RING_SIZE]);
		for (i = 0; i < TX_RING_SIZE; i++) {
			printk(KERN_DEBUG "  %d: @%p  length %8.8x status %8.8x\n", i,
				   &vp->tx_ring[i],
				   le32_to_cpu(vp->tx_ring[i].length),
				   le32_to_cpu(vp->tx_ring[i].status));
		}
	}
#endif
	wait_for_completion(dev, TxReset);

	vp->stats.tx_errors++;
	if (vp->full_bus_master_tx) {
		if (vortex_debug > 0)
			printk(KERN_DEBUG "%s: Resetting the Tx ring pointer.\n",
				   dev->name);
		if (vp->drv_flags & HAS_FIFO_BUG) /* Disable tx reclaim */
			outw(SetTxReclaim | 0xff, ioaddr + EL3_CMD);
		if (vp->cur_tx - vp->dirty_tx > 0  &&  inl(ioaddr + DownListPtr) == 0)
			outl(virt_to_bus(&vp->tx_ring[vp->dirty_tx % TX_RING_SIZE]),
				 ioaddr + DownListPtr);
		if (vp->tx_full && (vp->cur_tx - vp->dirty_tx <= TX_QUEUE_LEN - 1)) {
			vp->tx_full = 0;
			netif_start_queue(dev);
		}
		if ((vp->drv_flags & IS_BOOMERANG) || !down_poll_rate) {
			/* Room for a packet, to avoid long DownStall delays. */
			outb(PKT_BUF_SZ>>8, ioaddr + TxFreeThreshold);
			outw(DownUnstall, ioaddr + EL3_CMD);
		} else
			outb(down_poll_rate, ioaddr + DownPollRate);
	} else {
		netif_start_queue(dev);
		vp->stats.tx_dropped++;
	}
	
	/* Issue Tx Enable */
	outw(TxEnable, ioaddr + EL3_CMD);
	vp->restart_tx = 1;
	dev->trans_start = jiffies;
	
	/* Switch to register set 7 for normal use. */
	EL3WINDOW(7);
}

/*
 * Handle uncommon interrupt sources.  This is a separate routine to minimize
 * the cache impact.
 */
static void
vortex_error(struct net_device *dev, int status)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int do_tx_reset = 0;

	if (status & TxComplete) {			/* Really "TxError" for us. */
		unsigned char tx_status = inb(ioaddr + TxStatus);
		/* Presumably a tx-timeout. We must merely re-enable. */
		if (vortex_debug > 2
			|| (tx_status != 0x88 && vortex_debug > 0))
			printk(KERN_INFO "%s: Transmit error, Tx status register %2.2x.\n",
				   dev->name, tx_status);
		if (tx_status & 0x14)  vp->stats.tx_fifo_errors++;
		if (tx_status & 0x38)  vp->stats.tx_aborted_errors++;
		outb(0, ioaddr + TxStatus);
		if ((tx_status & 0x08) && (vp->drv_flags & IS_TORNADO))
			wait_for_completion(dev, TxReset | 0x0108);
		if (tx_status & 0x30)
			do_tx_reset = 1;
		else {					/* Merely re-enable the transmitter. */
			outw(TxEnable, ioaddr + EL3_CMD);
			vp->restart_tx = 1;
		}
	}
	if (status & RxEarly) {				/* Rx early is unused. */
		vortex_rx(dev);
		outw(AckIntr | RxEarly, ioaddr + EL3_CMD);
	}
	if (status & StatsFull) {			/* Empty statistics. */
		static int DoneDidThat = 0;
		if (vortex_debug > 4)
			printk(KERN_DEBUG "%s: Updating stats.\n", dev->name);
		update_stats(ioaddr, dev);
		/* HACK: Disable statistics as an interrupt source. */
		/* This occurs when we have the wrong media type! */
		if (DoneDidThat == 0  &&
			inw(ioaddr + EL3_STATUS) & StatsFull) {
			printk(KERN_WARNING "%s: Updating statistics failed, disabling "
				   "stats as an interrupt source.\n", dev->name);
			EL3WINDOW(5);
			outw(SetIntrEnb | (inw(ioaddr + 10) & ~StatsFull), ioaddr + EL3_CMD);
			EL3WINDOW(7);
			DoneDidThat++;
		}
	}
	if (status & IntReq) {
		/* Restore all interrupt sources.  */
		outw(vp->status_enable, ioaddr + EL3_CMD);
		outw(vp->intr_enable, ioaddr + EL3_CMD);
	}
	if (status & HostError) {
		u16 fifo_diag;
		EL3WINDOW(4);
		fifo_diag = inw(ioaddr + Wn4_FIFODiag);
		printk(KERN_ERR "%s: Host error, FIFO diagnostic register %4.4x.\n",
			   dev->name, fifo_diag);
		/* Adapter failure requires Tx/Rx reset and reinit. */
		if (vp->full_bus_master_tx) {
			if (vortex_debug)
				printk(KERN_ERR "%s: PCI bus error, bus status %8.8x.\n",
					   dev->name, inl(ioaddr + PktStatus));
			vortex_down(dev);
			wait_for_completion(dev, TotalReset | 0xff);
			vortex_up(dev);
		} else if (fifo_diag & 0x0400)
			do_tx_reset = 1;
		if (fifo_diag & 0x3000) {
			wait_for_completion(dev, RxReset);
			/* Set the Rx filter to the current state. */
			set_rx_mode(dev);
			outw(RxEnable, ioaddr + EL3_CMD); /* Re-enable the receiver. */
			outw(AckIntr | HostError, ioaddr + EL3_CMD);
		}
	}
	if (do_tx_reset) {
		wait_for_completion(dev, DownStall);
		wait_for_completion(dev, TxReset);
		outw(TxEnable, ioaddr + EL3_CMD);
		if ((vp->drv_flags & IS_BOOMERANG) || !down_poll_rate) {
			/* Room for a packet, to avoid long DownStall delays. */
			outb(PKT_BUF_SZ>>8, ioaddr + TxFreeThreshold);
			outw(DownUnstall, ioaddr + EL3_CMD);
		} else
			outb(down_poll_rate, ioaddr + DownPollRate);
		vp->restart_tx = 1;
	}

}


static int
vortex_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;

	tx_timeout_check(dev, vortex_tx_timeout);

	/* Put out the doubleword header... */
	outl(skb->len, ioaddr + TX_FIFO);
	if (vp->bus_master) {
		/* Set the bus-master controller to transfer the packet. */
		outl(virt_to_bus(skb->data), ioaddr + Wn7_MasterAddr);
		outw((skb->len + 3) & ~3, ioaddr + Wn7_MasterLen);
		vp->tx_skb = skb;
		outw(StartDMADown, ioaddr + EL3_CMD);
		/* queue will be restarted at the DMADone interrupt. */
	} else {
		/* ... and the packet rounded to a doubleword. */
		outsl(ioaddr + TX_FIFO, skb->data, (skb->len + 3) >> 2);
		dev_free_skb(skb);
		if (inw(ioaddr + TxFree) > 1536) {
			netif_start_queue(dev);
		} else
			/* Interrupt us when the FIFO has room for max-sized packet. */
			outw(SetTxThreshold + (1536>>2), ioaddr + EL3_CMD);
	}

	dev->trans_start = jiffies;

	/* Clear the Tx status stack. */
	{
		int tx_status;
		int i = 32;

		while (--i > 0	&&	(tx_status = inb(ioaddr + TxStatus)) > 0) {
			if (tx_status & 0x3C) {		/* A Tx-disabling error occurred.  */
				if (vortex_debug > 2)
				  printk(KERN_DEBUG "%s: Tx error, status %2.2x.\n",
						 dev->name, tx_status);
				if (tx_status & 0x04) vp->stats.tx_fifo_errors++;
				if (tx_status & 0x38) vp->stats.tx_aborted_errors++;
				if (tx_status & 0x30) {
					wait_for_completion(dev, TxReset);
				}
				outw(TxEnable, ioaddr + EL3_CMD);
				vp->restart_tx = 1;
			}
			outb(0x00, ioaddr + TxStatus); /* Pop the status stack. */
		}
	}
	return 0;
}

static int
boomerang_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int entry;
	struct boom_tx_desc *prev_entry;
	unsigned long flags;
	int i;

	tx_timeout_check(dev, vortex_tx_timeout);

	/* Calculate the next Tx descriptor entry. */
	entry = vp->cur_tx % TX_RING_SIZE;
	prev_entry = &vp->tx_ring[(vp->cur_tx-1) % TX_RING_SIZE];

	if (vortex_debug > 3)
		printk(KERN_DEBUG "%s: Queuing Tx packet, index %d.\n",
			   dev->name, vp->cur_tx);
	/* Impossible error. */
	if (vp->tx_full) {
		if (vortex_debug >0)
			printk(KERN_WARNING "%s: Tx Ring full, refusing to send buffer.\n",
				   dev->name);
		return 1;
	}
	vp->tx_skbuff[entry] = skb;
	vp->tx_ring[entry].next = 0;
	vp->tx_ring[entry].addr = virt_to_le32desc(skb->data);
	vp->tx_ring[entry].length = cpu_to_le32(skb->len | LAST_FRAG);
	vp->tx_ring[entry].status = cpu_to_le32(skb->len | TxIntrUploaded);

	spin_lock_irqsave(&vp->lock, flags);
	if ((vp->drv_flags & IS_BOOMERANG) || !down_poll_rate) {
		/* Wait for the stall to complete. */
		wait_for_completion(dev, DownStall);
		vp->tx_desc_tail->next = virt_to_le32desc(&vp->tx_ring[entry]);
		vp->tx_desc_tail = &vp->tx_ring[entry];
		if (inl(ioaddr + DownListPtr) == 0) {
			outl(virt_to_bus(&vp->tx_ring[entry]), ioaddr + DownListPtr);
			queued_packet++;
		}
		outw(DownUnstall, ioaddr + EL3_CMD);
	} else {
		vp->tx_desc_tail->next = virt_to_le32desc(&vp->tx_ring[entry]);
		vp->tx_desc_tail = &vp->tx_ring[entry];
		if (vp->restart_tx) {
			if (vp->drv_flags & HAS_FIFO_BUG) /* Disable tx reclaim */
				outw(SetTxReclaim | 0xff, ioaddr + EL3_CMD);
			outl(virt_to_bus(&vp->tx_ring[vp->dirty_tx % TX_RING_SIZE]),
				 ioaddr + DownListPtr);
			vp->restart_tx = 0;
			queued_packet++;
		}
	}
	vp->cur_tx++;
	if (vp->cur_tx - vp->dirty_tx >= TX_QUEUE_LEN)
		vp->tx_full = 1;
	else {					/* Clear previous interrupt enable. */
#if defined(tx_interrupt_mitigation)
		prev_entry->status &= cpu_to_le32(~TxIntrUploaded);
#endif
		netif_start_queue(dev);
	}
	spin_unlock_irqrestore(&vp->lock, flags);
	dev->trans_start = jiffies;
	return 0;
}

/* The interrupt handler does all of the Rx thread work and cleans up
   after the Tx thread. */
static void vortex_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = dev_id;
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr;
	int latency, status;
	int work_done = max_interrupt_work;

	ioaddr = dev->base_addr;
	latency = inb(ioaddr + Timer);
	status = inw(ioaddr + EL3_STATUS);
	if (status & IntReq) {
		status |= vp->deferred_irqs;
		vp->deferred_irqs = 0;
	}

	if (status == 0xffff)
		goto handler_exit;
	if (vortex_debug > 4)
		printk(KERN_DEBUG "%s: interrupt, status %4.4x, latency %d ticks.\n",
			   dev->name, status, latency);
	spin_lock(&vp->lock);
	do {
		if (vortex_debug > 5)
				printk(KERN_DEBUG "%s: In interrupt loop, status %4.4x.\n",
					   dev->name, status);
		if (status & RxComplete)
			vortex_rx(dev);
		if (status & UpComplete) {
			outw(AckIntr | UpComplete, ioaddr + EL3_CMD);
			boomerang_rx(dev);
		}

		if (status & TxAvailable) {
			if (vortex_debug > 5)
				printk(KERN_DEBUG "	TX room bit was handled.\n");
			/* There's room in the FIFO for a full-sized packet. */
			outw(AckIntr | TxAvailable, ioaddr + EL3_CMD);
			netif_wake_queue(dev);
		}

		if (status & DownComplete) {
			unsigned int dirty_tx = vp->dirty_tx;

			outw(AckIntr | DownComplete, ioaddr + EL3_CMD);
			while (vp->cur_tx - dirty_tx > 0) {
				int entry = dirty_tx % TX_RING_SIZE;
				if (inl(ioaddr + DownListPtr) ==
					virt_to_bus(&vp->tx_ring[entry]))
					break;			/* It still hasn't been processed. */
				if (vp->tx_skbuff[entry]) {
					dev_kfree_skb_irq(vp->tx_skbuff[entry]);
					vp->tx_skbuff[entry] = 0;
				}
				/* vp->stats.tx_packets++;  Counted below. */
				dirty_tx++;
			}
			vp->dirty_tx = dirty_tx;
			if (vp->tx_full && (vp->cur_tx - dirty_tx < TX_QUEUE_LEN)) {
				vp->tx_full = 0;
				netif_wake_queue(dev);
			}
		}
		if (status & DMADone) {
			if (inw(ioaddr + Wn7_MasterStatus) & 0x1000) {
				outw(0x1000, ioaddr + Wn7_MasterStatus); /* Ack the event. */
				dev_kfree_skb_irq(vp->tx_skb); /* Release the tx buffer */
				if (inw(ioaddr + TxFree) > 1536) {
					netif_wake_queue(dev);
				} else /* Interrupt when FIFO has room for max-sized packet. */
					outw(SetTxThreshold + (1536>>2), ioaddr + EL3_CMD);
			}
		}
		/* Check for all uncommon interrupts at once. */
		if (status & (HostError | RxEarly | StatsFull | TxComplete | IntReq)) {
			if (status == 0xffff)
				break;
			vortex_error(dev, status);
		}

		if (--work_done < 0) {
			printk(KERN_DEBUG "%s: Too much work in interrupt, status "
				   "%4.4x.\n", dev->name, status);
			/* Disable all pending interrupts. */
			do {
				vp->deferred_irqs |= status;
				outw(SetStatusEnb | (~vp->deferred_irqs & vp->status_enable),
					 ioaddr + EL3_CMD);
				outw(AckIntr | (vp->deferred_irqs & 0x7ff), ioaddr + EL3_CMD);
			} while ((status = inw(ioaddr + EL3_CMD)) & IntLatch);
			/* The timer will reenable interrupts. */
			del_timer(&vp->timer);
			vp->timer.expires = jiffies + 1;
			add_timer(&vp->timer);
			break;
		}
		/* Acknowledge the IRQ. */
		outw(AckIntr | IntReq | IntLatch, ioaddr + EL3_CMD);
		if (vp->cb_fn_base)			/* The PCMCIA people are idiots.  */
			writel(0x8000, vp->cb_fn_base + 4);

	} while ((status = inw(ioaddr + EL3_STATUS)) & (IntLatch | RxComplete));
	spin_unlock(&vp->lock);

	if (vortex_debug > 4)
		printk(KERN_DEBUG "%s: exiting interrupt, status %4.4x.\n",
			   dev->name, status);
handler_exit:
	return;
}

static int vortex_rx(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int i;
	short rx_status;

	if (vortex_debug > 5)
		printk(KERN_DEBUG"   In rx_packet(), status %4.4x, rx_status %4.4x.\n",
			   inw(ioaddr+EL3_STATUS), inw(ioaddr+RxStatus));
	while ((rx_status = inw(ioaddr + RxStatus)) > 0) {
		if (rx_status & 0x4000) { /* Error, update stats. */
			unsigned char rx_error = inb(ioaddr + RxErrors);
			if (vortex_debug > 2)
				printk(KERN_DEBUG " Rx error: status %2.2x.\n", rx_error);
			vp->stats.rx_errors++;
			if (rx_error & 0x01)  vp->stats.rx_over_errors++;
			if (rx_error & 0x02)  vp->stats.rx_length_errors++;
			if (rx_error & 0x04)  vp->stats.rx_frame_errors++;
			if (rx_error & 0x08)  vp->stats.rx_crc_errors++;
			if (rx_error & 0x10)  vp->stats.rx_length_errors++;
		} else {
			/* The packet length: up to 4.5K!. */
			int pkt_len = rx_status & 0x1fff;
			struct sk_buff *skb;

			skb = dev_alloc_skb(pkt_len + 5);
			if (vortex_debug > 4)
				printk(KERN_DEBUG "Receiving packet size %d status %4.4x.\n",
					   pkt_len, rx_status);
			if (skb != NULL) {
				skb->dev = dev;
				skb_reserve(skb, 2);	/* Align IP on 16 byte boundaries */
				/* 'skb_put()' points to the start of sk_buff data area. */
				if (vp->bus_master &&
					! (inw(ioaddr + Wn7_MasterStatus) & 0x8000)) {
					outl(virt_to_bus(skb_put(skb, pkt_len)),
						 ioaddr + Wn7_MasterAddr);
					outw((skb->len + 3) & ~3, ioaddr + Wn7_MasterLen);
					outw(StartDMAUp, ioaddr + EL3_CMD);
					while (inw(ioaddr + Wn7_MasterStatus) & 0x8000)
						;
				} else {
					insl(ioaddr + RX_FIFO, skb_put(skb, pkt_len),
						 (pkt_len + 3) >> 2);
				}
				outw(RxDiscard, ioaddr + EL3_CMD); /* Pop top Rx packet. */
				skb->protocol = eth_type_trans(skb, dev);
				netif_rx(skb);
				dev->last_rx = jiffies;
				vp->stats.rx_packets++;
				/* Wait a limited time to go to next packet. */
				for (i = 200; i >= 0; i--)
					if ( ! (inw(ioaddr + EL3_STATUS) & CmdInProgress))
						break;
				continue;
			} else if (vortex_debug)
				printk(KERN_NOTICE "%s: No memory to allocate a sk_buff of "
					   "size %d.\n", dev->name, pkt_len);
		}
		vp->stats.rx_dropped++;
		wait_for_completion(dev, RxDiscard);
	}

	return 0;
}

static int
boomerang_rx(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	int entry = vp->cur_rx % RX_RING_SIZE;
	long ioaddr = dev->base_addr;
	int rx_status;
	int rx_work_limit = vp->dirty_rx + RX_RING_SIZE - vp->cur_rx;

	if (vortex_debug > 5)
		printk(KERN_DEBUG "  In boomerang_rx(), status %4.4x, rx_status "
			   "%4.4x.\n",
			   inw(ioaddr+EL3_STATUS), inw(ioaddr+RxStatus));
	while ((rx_status = le32_to_cpu(vp->rx_ring[entry].status)) & RxDComplete){
		if (--rx_work_limit < 0)
			break;
		if (rx_status & RxDError) { /* Error, update stats. */
			unsigned char rx_error = rx_status >> 16;
			if (vortex_debug > 2)
				printk(KERN_DEBUG " Rx error: status %2.2x.\n", rx_error);
			vp->stats.rx_errors++;
			if (rx_error & 0x01)  vp->stats.rx_over_errors++;
			if (rx_error & 0x02)  vp->stats.rx_length_errors++;
			if (rx_error & 0x04)  vp->stats.rx_frame_errors++;
			if (rx_error & 0x08)  vp->stats.rx_crc_errors++;
			if (rx_error & 0x10)  vp->stats.rx_length_errors++;
		} else {
			/* The packet length: up to 4.5K!. */
			int pkt_len = rx_status & 0x1fff;
			struct sk_buff *skb;

			if (vortex_debug > 4)
				printk(KERN_DEBUG "Receiving packet size %d status %4.4x.\n",
					   pkt_len, rx_status);

			/* Check if the packet is long enough to just accept without
			   copying to a properly sized skbuff. */
			if (pkt_len < rx_copybreak
				&& (skb = dev_alloc_skb(pkt_len + 2)) != 0) {
				skb->dev = dev;
				skb_reserve(skb, 2);	/* Align IP on 16 byte boundaries */
				/* 'skb_put()' points to the start of sk_buff data area. */
				memcpy(skb_put(skb, pkt_len),
					   le32desc_to_virt(vp->rx_ring[entry].addr), pkt_len);
				rx_copy++;
			} else {
				void *temp;
				/* Pass up the skbuff already on the Rx ring. */
				skb = vp->rx_skbuff[entry];
				vp->rx_skbuff[entry] = NULL;
				temp = skb_put(skb, pkt_len);
				/* Remove this checking code for final release. */
				if (le32desc_to_virt(vp->rx_ring[entry].addr) != temp)
					printk(KERN_ERR "%s: Warning -- the skbuff addresses do not match"
						   " in boomerang_rx: %p vs. %p.\n", dev->name,
						   le32desc_to_virt(vp->rx_ring[entry].addr),
						   temp);
				rx_nocopy++;
			}
			skb->protocol = eth_type_trans(skb, dev);
			if (use_hw_csums) {
				int csum_bits = rx_status & 0xee000000;
				if (csum_bits &&
					(csum_bits == (IPChksumValid | TCPChksumValid) ||
					 csum_bits == (IPChksumValid | UDPChksumValid))) {
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					rx_csumhits++;
				}
			}
			netif_rx(skb);
			dev->last_rx = jiffies;
			vp->stats.rx_packets++;
		}
		entry = (++vp->cur_rx) % RX_RING_SIZE;
	}
	/* Refill the Rx ring buffers. */
	for (; vp->cur_rx - vp->dirty_rx > 0; vp->dirty_rx++) {
		struct sk_buff *skb;
		entry = vp->dirty_rx % RX_RING_SIZE;
		if (vp->rx_skbuff[entry] == NULL) {
			skb = dev_alloc_skb(PKT_BUF_SZ);
			if (skb == NULL)
				break;			/* Bad news!  */
			skb->dev = dev;			/* Mark as being used by this device. */
			skb_reserve(skb, 2);	/* Align IP on 16 byte boundaries */
			vp->rx_ring[entry].addr = virt_to_le32desc(skb->tail);
			vp->rx_skbuff[entry] = skb;
		}
		vp->rx_ring[entry].status = 0;	/* Clear complete bit. */
		outw(UpUnstall, ioaddr + EL3_CMD);
	}
	return 0;
}

static void
vortex_down(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;

	del_timer(&vp->timer);

	/* Turn off statistics ASAP.  We update vp->stats below. */
	outw(StatsDisable, ioaddr + EL3_CMD);

	/* Disable the receiver and transmitter. */
	outw(RxDisable, ioaddr + EL3_CMD);
	outw(TxDisable, ioaddr + EL3_CMD);

	if (dev->if_port == XCVR_10base2)
		/* Turn off thinnet power.  Green! */
		outw(StopCoax, ioaddr + EL3_CMD);

	outw(SetIntrEnb | 0x0000, ioaddr + EL3_CMD);

	update_stats(ioaddr, dev);
	if (vp->full_bus_master_rx)
		outl(0, ioaddr + UpListPtr);
	if (vp->full_bus_master_tx)
		outl(0, ioaddr + DownListPtr);

	if (vp->capabilities & CapPwrMgmt)
		acpi_set_WOL(dev);
}

static int
vortex_close(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int i;

	if (netif_device_present(dev)) {
		netif_stop_queue(dev);
		netif_mark_down(dev);
		vortex_down(dev);
	}

	if (vortex_debug > 1) {
		printk(KERN_DEBUG"%s: vortex_close() status %4.4x, Tx status %2.2x.\n",
			   dev->name, inw(ioaddr + EL3_STATUS), inb(ioaddr + TxStatus));
		printk(KERN_DEBUG "%s: vortex close stats: rx_nocopy %d rx_copy %d"
			   " tx_queued %d Rx pre-checksummed %d.\n",
			   dev->name, rx_nocopy, rx_copy, queued_packet, rx_csumhits);
	}

	free_irq(dev->irq, dev);

	if (vp->full_bus_master_rx) { /* Free Boomerang bus master Rx buffers. */
		for (i = 0; i < RX_RING_SIZE; i++)
			if (vp->rx_skbuff[i]) {
#if LINUX_VERSION_CODE < 0x20100
				vp->rx_skbuff[i]->free = 1;
#endif
				dev_free_skb(vp->rx_skbuff[i]);
				vp->rx_skbuff[i] = 0;
			}
	}
	if (vp->full_bus_master_tx) { /* Free Boomerang bus master Tx buffers. */
		for (i = 0; i < TX_RING_SIZE; i++)
			if (vp->tx_skbuff[i]) {
				dev_free_skb(vp->tx_skbuff[i]);
				vp->tx_skbuff[i] = 0;
			}
	}

	MOD_DEC_USE_COUNT;
	vp->open = 0;
	return 0;
}

static struct net_device_stats *vortex_get_stats(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	unsigned long flags;

	if (netif_device_present(dev)) {
		spin_lock_irqsave(&vp->lock, flags);
		update_stats(dev->base_addr, dev);
		spin_unlock_irqrestore(&vp->lock, flags);
	}
	return &vp->stats;
}

/*  Update statistics.
	Unlike with the EL3 we need not worry about interrupts changing
	the window setting from underneath us, but we must still guard
	against a race condition with a StatsUpdate interrupt updating the
	table.  This is done by checking that the ASM (!) code generated uses
	atomic updates with '+='.
	*/
static void update_stats(long ioaddr, struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	int old_window = inw(ioaddr + EL3_CMD);

	if (old_window == 0xffff)	/* Chip suspended or ejected. */
		return;
	/* Unlike the 3c5x9 we need not turn off stats updates while reading. */
	/* Switch to the stats window, and read everything. */
	EL3WINDOW(6);
	vp->stats.tx_carrier_errors		+= inb(ioaddr + 0);
	vp->stats.tx_heartbeat_errors	+= inb(ioaddr + 1);
	/* Multiple collisions. */		inb(ioaddr + 2);
	vp->stats.collisions			+= inb(ioaddr + 3);
	vp->stats.tx_window_errors		+= inb(ioaddr + 4);
	vp->stats.rx_fifo_errors		+= inb(ioaddr + 5);
	vp->stats.tx_packets			+= inb(ioaddr + 6);
	vp->stats.tx_packets			+= (inb(ioaddr + 9)&0x30) << 4;
	/* Rx packets	*/				inb(ioaddr + 7);   /* Must read to clear */
	/* Tx deferrals */				inb(ioaddr + 8);
	/* Don't bother with register 9, an extension of registers 6&7.
	   If we do use the 6&7 values the atomic update assumption above
	   is invalid. */
#if LINUX_VERSION_CODE > 0x020119
	vp->stats.rx_bytes += inw(ioaddr + 10);
	vp->stats.tx_bytes += inw(ioaddr + 12);
#else
	inw(ioaddr + 10);
	inw(ioaddr + 12);
#endif
	/* New: On the Vortex we must also clear the BadSSD counter. */
	EL3WINDOW(4);
	inb(ioaddr + 12);

#if LINUX_VERSION_CODE > 0x020119
	{
		u8 up = inb(ioaddr + 13);
		vp->stats.rx_bytes += (up & 0x0f) << 16;
		vp->stats.tx_bytes += (up & 0xf0) << 12;
	}
#endif

	/* We change back to window 7 (not 1) with the Vortex. */
	EL3WINDOW(old_window >> 13);
	return;
}

static int vortex_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;
	u16 *data = (u16 *)&rq->ifr_data;
	int phy = vp->phys[0] & 0x1f;
	int retval;

	spin_lock(&vp->lock);

	switch(cmd) {
	case SIOCDEVPRIVATE:		/* Get the address of the PHY in use. */
		data[0] = phy;
	case SIOCDEVPRIVATE+1:		/* Read the specified MII register. */
		EL3WINDOW(4);
		data[3] = mdio_read(ioaddr, data[0] & 0x1f, data[1] & 0x1f);
		retval = 0;
		break;
	case SIOCDEVPRIVATE+2:		/* Write the specified MII register */
		if (!capable(CAP_NET_ADMIN)) {
			retval = -EPERM;
		} else {
			if (data[0] == vp->phys[0]) {
				u16 value = data[2];
				switch (data[1]) {
				case 0:
					/* Check for autonegotiation on or reset. */
					vp->medialock = (value & 0x9000) ? 0 : 1;
					if (vp->medialock)
						vp->full_duplex = (value & 0x0100) ? 1 : 0;
					break;
				case 4: vp->advertising = value; break;
				}
				/* Perhaps check_duplex(dev), depending on chip semantics. */
			}
			EL3WINDOW(4);
			mdio_write(ioaddr, data[0] & 0x1f, data[1] & 0x1f, data[2]);
			retval = 0;
		}
		break;
	default:
		retval = -EOPNOTSUPP;
	}

	spin_unlock(&vp->lock);
	return retval;
}

/* Pre-Cyclone chips have no documented multicast filter, so the only
   multicast setting is to receive all multicast frames.  At least
   the chip has a very clean way to set the mode, unlike many others. */
static void set_rx_mode(struct net_device *dev)
{
	long ioaddr = dev->base_addr;
	int new_mode;

	if (dev->flags & IFF_PROMISC) {
		if (vortex_debug > 0)
			printk(KERN_NOTICE "%s: Setting promiscuous mode.\n", dev->name);
		new_mode = SetRxFilter|RxStation|RxMulticast|RxBroadcast|RxProm;
	} else	if ((dev->mc_list)  ||  (dev->flags & IFF_ALLMULTI)) {
		new_mode = SetRxFilter|RxStation|RxMulticast|RxBroadcast;
	} else
		new_mode = SetRxFilter | RxStation | RxBroadcast;

	outw(new_mode, ioaddr + EL3_CMD);
}


/* MII transceiver control section.
   Read and write the MII registers using software-generated serial
   MDIO protocol.  See the MII specifications or DP83840A data sheet
   for details. */

/* The maximum data clock rate is 2.5 Mhz.  The minimum timing is usually
   met by back-to-back PCI I/O cycles, but we insert a delay to avoid
   "overclocking" issues. */
#define mdio_delay() inl(mdio_addr)

#define MDIO_SHIFT_CLK	0x01
#define MDIO_DIR_WRITE	0x04
#define MDIO_DATA_WRITE0 (0x00 | MDIO_DIR_WRITE)
#define MDIO_DATA_WRITE1 (0x02 | MDIO_DIR_WRITE)
#define MDIO_DATA_READ	0x02
#define MDIO_ENB_IN		0x00

/* Generate the preamble required for initial synchronization and
   a few older transceivers. */
static void mdio_sync(long ioaddr, int bits)
{
	long mdio_addr = ioaddr + Wn4_PhysicalMgmt;

	/* Establish sync by sending at least 32 logic ones. */
	while (-- bits >= 0) {
		outw(MDIO_DATA_WRITE1, mdio_addr);
		mdio_delay();
		outw(MDIO_DATA_WRITE1 | MDIO_SHIFT_CLK, mdio_addr);
		mdio_delay();
	}
}

static int mdio_read(long ioaddr, int phy_id, int location)
{
	int i;
	int read_cmd = (0xf6 << 10) | (phy_id << 5) | location;
	unsigned int retval = 0;
	long mdio_addr = ioaddr + Wn4_PhysicalMgmt;

	if (mii_preamble_required)
		mdio_sync(ioaddr, 32);

	/* Shift the read command bits out. */
	for (i = 14; i >= 0; i--) {
		int dataval = (read_cmd&(1<<i)) ? MDIO_DATA_WRITE1 : MDIO_DATA_WRITE0;
		outw(dataval, mdio_addr);
		mdio_delay();
		outw(dataval | MDIO_SHIFT_CLK, mdio_addr);
		mdio_delay();
	}
	/* Read the two transition, 16 data, and wire-idle bits. */
	for (i = 19; i > 0; i--) {
		outw(MDIO_ENB_IN, mdio_addr);
		mdio_delay();
		retval = (retval << 1) | ((inw(mdio_addr) & MDIO_DATA_READ) ? 1 : 0);
		outw(MDIO_ENB_IN | MDIO_SHIFT_CLK, mdio_addr);
		mdio_delay();
	}
	return retval & 0x20000 ? 0xffff : retval>>1 & 0xffff;
}

static void mdio_write(long ioaddr, int phy_id, int location, int value)
{
	int write_cmd = 0x50020000 | (phy_id << 23) | (location << 18) | value;
	long mdio_addr = ioaddr + Wn4_PhysicalMgmt;
	int i;

	if (mii_preamble_required)
		mdio_sync(ioaddr, 32);

	/* Shift the command bits out. */
	for (i = 31; i >= 0; i--) {
		int dataval = (write_cmd&(1<<i)) ? MDIO_DATA_WRITE1 : MDIO_DATA_WRITE0;
		outw(dataval, mdio_addr);
		mdio_delay();
		outw(dataval | MDIO_SHIFT_CLK, mdio_addr);
		mdio_delay();
	}
	/* Leave the interface idle. */
	for (i = 1; i >= 0; i--) {
		outw(MDIO_ENB_IN, mdio_addr);
		mdio_delay();
		outw(MDIO_ENB_IN | MDIO_SHIFT_CLK, mdio_addr);
		mdio_delay();
	}

	return;
}

/* ACPI: Advanced Configuration and Power Interface. */
/* Set Wake-On-LAN mode and put the board into D3 (power-down) state. */
static void acpi_set_WOL(struct net_device *dev)
{
	struct vortex_private *vp = (struct vortex_private *)dev->priv;
	long ioaddr = dev->base_addr;

	/* Power up on: 1==Downloaded Filter, 2==Magic Packets, 4==Link Status. */
	EL3WINDOW(7);
	outw(2, ioaddr + 0x0c);
	/* The RxFilter must accept the WOL frames. */
	outw(SetRxFilter|RxStation|RxMulticast|RxBroadcast, ioaddr + EL3_CMD);
	outw(RxEnable, ioaddr + EL3_CMD);
	/* Change the power state to D3; RxEnable doesn't take effect. */
	pcibios_write_config_word(vp->pci_bus, vp->pci_devfn, 0xe0, 0x8103);
}
/* Change from D3 (sleep) to D0 (active).
   Problem: The Cyclone forgets all PCI config info during the transition! */
static void acpi_wake(int bus, int devfn)
{
	u32 base0, base1, romaddr;
	u16 pci_command, pwr_command;
	u8  pci_latency, pci_cacheline, irq;

	pcibios_read_config_word(bus, devfn, 0xe0, &pwr_command);
	if ((pwr_command & 3) == 0)
		return;
	pcibios_read_config_word( bus, devfn, PCI_COMMAND, &pci_command);
	pcibios_read_config_dword(bus, devfn, PCI_BASE_ADDRESS_0, &base0);
	pcibios_read_config_dword(bus, devfn, PCI_BASE_ADDRESS_1, &base1);
	pcibios_read_config_dword(bus, devfn, PCI_ROM_ADDRESS, &romaddr);
	pcibios_read_config_byte( bus, devfn, PCI_LATENCY_TIMER, &pci_latency);
	pcibios_read_config_byte( bus, devfn, PCI_CACHE_LINE_SIZE, &pci_cacheline);
	pcibios_read_config_byte( bus, devfn, PCI_INTERRUPT_LINE, &irq);

	pcibios_write_config_word( bus, devfn, 0xe0, 0x0000);
	pcibios_write_config_dword(bus, devfn, PCI_BASE_ADDRESS_0, base0);
	pcibios_write_config_dword(bus, devfn, PCI_BASE_ADDRESS_1, base1);
	pcibios_write_config_dword(bus, devfn, PCI_ROM_ADDRESS, romaddr);
	pcibios_write_config_byte( bus, devfn, PCI_INTERRUPT_LINE, irq);
	pcibios_write_config_byte( bus, devfn, PCI_LATENCY_TIMER, pci_latency);
	pcibios_write_config_byte( bus, devfn, PCI_CACHE_LINE_SIZE, pci_cacheline);
	pcibios_write_config_word( bus, devfn, PCI_COMMAND, pci_command | 5);
}


#ifdef MODULE
void cleanup_module(void)
{
	struct net_device *next_dev;

#ifdef CARDBUS
	unregister_driver(&vortex_ops);
	vortex_reap();
#endif

	/* No need to check MOD_IN_USE, as sys_delete_module() checks. */
	while (root_vortex_dev) {
		struct vortex_private *vp=(void *)(root_vortex_dev->priv);
		unregister_netdev(root_vortex_dev);
		outw(TotalReset, root_vortex_dev->base_addr + EL3_CMD);
		release_region(root_vortex_dev->base_addr,
					   pci_tbl[vp->chip_id].io_size);
		next_dev = vp->next_module;
		if (vp->priv_addr)
			kfree(vp->priv_addr);
		kfree(root_vortex_dev);
		root_vortex_dev = next_dev;
	}
}

#endif  /* MODULE */

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
