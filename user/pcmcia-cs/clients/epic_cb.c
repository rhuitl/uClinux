/* epic100.c: A SMC 83c170 EPIC/100 Fast Ethernet driver for Linux. */
/*
	Written/copyright 1997-1999 by Donald Becker.

	This software may be used and distributed according to the terms
	of the GNU Public License, incorporated herein by reference.
	All other rights reserved.

	This driver is for the SMC83c170/175 "EPIC" series, as used on the
	SMC EtherPower II 9432 PCI adapter, and several CardBus cards.

	The author may be reached as becker@CESDIS.gsfc.nasa.gov, or C/O
	USRA Center of Excellence in Space Data and Information Sciences
	   Code 930.5, Goddard Space Flight Center, Greenbelt MD 20771

	Information and updates available at
	http://cesdis.gsfc.nasa.gov/linux/drivers/epic100.html
*/

static const char *version =
"epic100.c:v1.07h 8/18/99 Donald Becker http://cesdis.gsfc.nasa.gov/linux/drivers/epic100.html\n";

/* User-tunable values. */

static int debug = 1;
#define epic_debug debug

/* Used to pass the full-duplex flag, etc. */
#define MAX_UNITS 8
static int full_duplex[MAX_UNITS] = {-1, -1, -1, -1, -1, -1, -1, -1};
static int options[MAX_UNITS] = {-1, -1, -1, -1, -1, -1, -1, -1};

/* Set the copy breakpoint for the copy-only-tiny-frames scheme.
   Setting to > 1518 effectively disables this feature. */
static int rx_copybreak = 200;

/* Maximum events (Rx packets, etc.) to handle at each interrupt. */
static int max_interrupt_work = 32;

/* Operational parameters that usually are not changed. */
/* Keep the ring sizes a power of two for efficiency.
   Making the Tx ring too large decreases the effectiveness of channel
   bonding and packet priority.
   There are no ill effects from too-large receive rings. */
#define TX_RING_SIZE	16
#define RX_RING_SIZE	32

/* Time in jiffies before concluding the transmitter is hung. */
#define TX_TIMEOUT  (2*HZ)

#define PKT_BUF_SZ		1536			/* Size of each temporary Rx buffer.*/

/* Bytes transferred to chip before transmission starts. */
/* Initial threshold, increased on underflow, rounded down to 4 byte units. */
#define TX_FIFO_THRESH 256
#define RX_FIFO_THRESH 1		/* 0-3, 0==32, 64,96, or 3==128 bytes  */

#include <linux/version.h>		/* Evil, but neccessary */
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
#include <linux/delay.h>

#include <asm/processor.h>		/* Processor type for cache alignment. */
#include <asm/bitops.h>
#include <asm/io.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

/* Kernel compatibility defines, common to David Hind's PCMCIA package.
   This is only in the support-all-kernels source code. */

#if ! defined (LINUX_VERSION_CODE) || LINUX_VERSION_CODE < 0x20000
#warning This driver version is only for kernel versions 2.0.0 and later.
#endif

MODULE_AUTHOR("Donald Becker <becker@cesdis.gsfc.nasa.gov>");
MODULE_DESCRIPTION("SMC 83c170 EPIC series Ethernet driver");
MODULE_PARM(debug, "i");
MODULE_PARM(options, "1-" __MODULE_STRING(8) "i");
MODULE_PARM(full_duplex, "1-" __MODULE_STRING(8) "i");
MODULE_PARM(rx_copybreak, "i");
MODULE_PARM(max_interrupt_work, "i");
#if LINUX_VERSION_CODE < 0x20123
#define test_and_set_bit(val, addr) set_bit(val, addr)
typedef long spinlock_t;
#define SPIN_LOCK_UNLOCKED 0
#define spin_lock(lock)
#define spin_unlock(lock)
#define spin_lock_irqsave(lock, flags)	save_flags(flags); cli();
#define spin_unlock_irqrestore(lock, flags) restore_flags(flags);
#endif
#if LINUX_VERSION_CODE >= 0x20155
#define PCI_SUPPORT_VER2
#endif
#if LINUX_VERSION_CODE < 0x20159
#define dev_free_skb(skb) dev_kfree_skb(skb, FREE_WRITE);
#else  /* Grrr, unneeded incompatible change. */
#define dev_free_skb(skb) dev_kfree_skb(skb);
#endif
#if ! defined(CAP_NET_ADMIN)
#define capable(CAP_XXX) (suser())
#endif

/* The I/O extent. */
#define EPIC_TOTAL_SIZE 0x100

/*
				Theory of Operation

I. Board Compatibility

This device driver is designed for the SMC "EPIC/100", the SMC
single-chip Ethernet controllers for PCI.  This chip is used on
the SMC EtherPower II boards.

II. Board-specific settings

PCI bus devices are configured by the system at boot time, so no jumpers
need to be set on the board.  The system BIOS will assign the
PCI INTA signal to a (preferably otherwise unused) system IRQ line.
Note: Kernel versions earlier than 1.3.73 do not support shared PCI
interrupt lines.

III. Driver operation

IIIa. Ring buffers

IVb. References

http://www.smsc.com/main/datasheets/83c171.pdf
http://www.smsc.com/main/datasheets/83c175.pdf
http://cesdis.gsfc.nasa.gov/linux/misc/NWay.html
http://www.national.com/pf/DP/DP83840A.html

IVc. Errata

*/

/* The rest of these values should never change. */

static struct net_device *epic_probe1(int pci_bus, int pci_devfn,
								  struct net_device *dev, long ioaddr, int irq,
								  int chip_id, int card_idx);

/* For 2.2 resource management we are kind of stuck with this */
#define USE_IO

								  
#ifdef USE_IO
#define EPIC_USE_IO
#define EPIC_IOTYPE PCI_USES_MASTER|PCI_USES_IO|PCI_ADDR0
#else
#define EPIC_IOTYPE PCI_USES_MASTER|PCI_USES_MEM|PCI_ADDR1
#endif

enum pci_flags_bit {
	PCI_USES_IO=1, PCI_USES_MEM=2, PCI_USES_MASTER=4,
	PCI_ADDR0=0x10<<0, PCI_ADDR1=0x10<<1, PCI_ADDR2=0x10<<2, PCI_ADDR3=0x10<<3,
};

struct chip_info {
	const char *name;
	u16	vendor_id, device_id, device_id_mask, pci_flags;
	int io_size, min_latency;
	struct net_device *(*probe1)(int pci_bus, int pci_devfn, struct net_device *dev,
							 long ioaddr, int irq, int chip_idx, int fnd_cnt);
} static chip_tbl[] = {
	{"SMSC EPIC/100 83c170", 0x10B8, 0x0005, 0x7fff,
	 EPIC_IOTYPE, EPIC_TOTAL_SIZE, 32, epic_probe1},
	{"SMSC EPIC/C 83c175", 0x10B8, 0x0006, 0x7fff,
	 EPIC_IOTYPE, EPIC_TOTAL_SIZE, 32, epic_probe1},
	{0,},
};

/* This matches the table above. */
static enum { MII_PWRDWN=1, TYPE2_INTR=2 } chip_features[] ={
	TYPE2_INTR, TYPE2_INTR | MII_PWRDWN, };

/* Offsets to registers, using the (ugh) SMC names. */
enum epic_registers {
  COMMAND=0, INTSTAT=4, INTMASK=8, GENCTL=0x0C, NVCTL=0x10, EECTL=0x14,
  PCIBurstCnt=0x18,
  TEST1=0x1C, CRCCNT=0x20, ALICNT=0x24, MPCNT=0x28,	/* Rx error counters. */
  MIICtrl=0x30, MIIData=0x34, MIICfg=0x38,
  LAN0=64,						/* MAC address. */
  MC0=80,						/* Multicast filter table. */
  RxCtrl=96, TxCtrl=112, TxSTAT=0x74,
  PRxCDAR=0x84, RxSTAT=0xA4, EarlyRx=0xB0, PTxCDAR=0xC4, TxThresh=0xDC,
};

/* Interrupt register bits, using my own meaningful names. */
enum IntrStatus {
	TxIdle=0x40000, RxIdle=0x20000, IntrSummary=0x010000,
	PCIBusErr170=0x7000, PCIBusErr175=0x1000, PhyEvent175=0x8000,
	RxStarted=0x0800, RxEarlyWarn=0x0400, CntFull=0x0200, TxUnderrun=0x0100,
	TxEmpty=0x0080, TxDone=0x0020, RxError=0x0010,
	RxOverflow=0x0008, RxFull=0x0004, RxHeader=0x0002, RxDone=0x0001,
};
enum CommandBits {
	StopRx=1, StartRx=2, TxQueued=4, RxQueued=8,
	StopTxDMA=0x20, StopRxDMA=0x40, RestartTx=0x80,
};

static u16 media2miictl[16] = {
	0, 0x0C00, 0x0C00, 0x2000,  0x0100, 0x2100, 0, 0,
	0, 0, 0, 0,  0, 0, 0, 0 };

/* The EPIC100 Rx and Tx buffer descriptors. */

struct epic_tx_desc {
	s16 status;
	u16 txlength;
	u32 bufaddr;
	u16 buflength;
	u16 control;
	u32 next;
};

struct epic_rx_desc {
	s16 status;
	u16 rxlength;
	u32 bufaddr;
	u32 buflength;
	u32 next;
};

struct epic_private {
	char devname[8];			/* Used only for kernel debugging. */
	const char *product_name;
	struct net_device *next_module;

	/* Tx and Rx rings here so that they remain paragraph aligned. */
	struct epic_rx_desc rx_ring[RX_RING_SIZE];
	struct epic_tx_desc tx_ring[TX_RING_SIZE];
	/* The saved address of a sent-in-place packet/buffer, for skfree(). */
	struct sk_buff* tx_skbuff[TX_RING_SIZE];
	/* The addresses of receive-in-place skbuffs. */
	struct sk_buff* rx_skbuff[RX_RING_SIZE];

	/* Ring pointers. */
	spinlock_t lock;				/* Group with Tx control cache line. */
	unsigned int cur_tx, dirty_tx;
	struct descriptor  *last_tx_desc;
	unsigned int cur_rx, dirty_rx;
	struct descriptor  *last_rx_desc;
	long last_rx_time;				/* Last Rx, in jiffies. */

	u8 pci_bus, pci_dev_fn;				/* PCI bus location. */
	u16 chip_flags;

	struct net_device_stats stats;
	struct timer_list timer;			/* Media selection timer. */
	int tx_threshold;
	unsigned char mc_filter[8];
	signed char phys[4];				/* MII device addresses. */
	int mii_phy_cnt;
	unsigned int tx_full:1;				/* The Tx queue is full. */
	unsigned int full_duplex:1;			/* Current duplex setting. */
	unsigned int force_fd:1;			/* Full-duplex operation requested. */
	unsigned int default_port:4;		/* Last dev->if_port value. */
	unsigned int media2:4;				/* Secondary monitored media port. */
	unsigned int medialock:1;			/* Don't sense media type. */
	unsigned int mediasense:1;			/* Media sensing in progress. */
	int pad0, pad1;						/* Used for 8-byte alignment */
};

static int epic_open(struct net_device *dev);
static int read_eeprom(long ioaddr, int location);
static int mdio_read(long ioaddr, int phy_id, int location);
static void mdio_write(long ioaddr, int phy_id, int location, int value);
static void epic_restart(struct net_device *dev);
static void epic_timer(unsigned long data);
static void epic_tx_timeout(struct net_device *dev);
static void epic_init_ring(struct net_device *dev);
static int epic_start_xmit(struct sk_buff *skb, struct net_device *dev);
static int epic_rx(struct net_device *dev);
static void epic_interrupt(int irq, void *dev_instance, struct pt_regs *regs);
static int mii_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);
static int epic_close(struct net_device *dev);
static struct net_device_stats *epic_get_stats(struct net_device *dev);
static void set_rx_mode(struct net_device *dev);


/* A list of all installed EPIC devices, for removing the driver module. */
static struct net_device *root_epic_dev = NULL;

#ifndef CARDBUS
int epic100_probe(struct net_device *dev)
{
	int cards_found = 0;
	int chip_idx, irq;
	u16 pci_command, new_command;
	unsigned char pci_bus, pci_device_fn;

#ifdef PCI_SUPPORT_VER2
	struct pci_dev *pcidev = NULL;
	while ((pcidev = pci_find_class(PCI_CLASS_NETWORK_ETHERNET << 8, pcidev))
			!= NULL) {
		long pci_ioaddr = pcidev->base_address[0] & ~3;
		int vendor = pcidev->vendor;
		int device = pcidev->device;

		for (chip_idx = 0; chip_tbl[chip_idx].vendor_id; chip_idx++)
			if (vendor == chip_tbl[chip_idx].vendor_id
				&& (device & chip_tbl[chip_idx].device_id_mask) ==
				chip_tbl[chip_idx].device_id)
				break;
		if (chip_tbl[chip_idx].vendor_id == 0)		/* Compiled out! */
			continue;
		pci_bus = pcidev->bus->number;
		pci_device_fn = pcidev->devfn;
		irq = pcidev->irq;
#else
	int pci_index;

	if ( ! pcibios_present())
		return -ENODEV;

	for (pci_index = 0; pci_index < 0xff; pci_index++) {
		u8 pci_irq_line;
		u16 vendor, device;
		u32 pci_ioaddr;

		if (pcibios_find_class (PCI_CLASS_NETWORK_ETHERNET << 8,
								pci_index, &pci_bus, &pci_device_fn)
			!= PCIBIOS_SUCCESSFUL)
			break;
		pcibios_read_config_word(pci_bus, pci_device_fn,
								 PCI_VENDOR_ID, &vendor);
		pcibios_read_config_word(pci_bus, pci_device_fn,
								 PCI_DEVICE_ID, &device);

		for (chip_idx = 0; chip_tbl[chip_idx].vendor_id; chip_idx++)
			if (vendor == chip_tbl[chip_idx].vendor_id
				&& (device & chip_tbl[chip_idx].device_id_mask) ==
				chip_tbl[chip_idx].device_id)
				break;
		if (chip_tbl[chip_idx].vendor_id == 0) 		/* Compiled out! */
			continue;

		pcibios_read_config_dword(pci_bus, pci_device_fn,
								  PCI_BASE_ADDRESS_0, &pci_ioaddr);
		pcibios_read_config_byte(pci_bus, pci_device_fn,
								 PCI_INTERRUPT_LINE, &pci_irq_line);
		/* Remove I/O space marker in bit 0. */
		pci_ioaddr &= ~3;
		irq = pci_irq_line;

		if (check_region(pci_ioaddr, chip_tbl[chip_idx].io_size))
			continue;
#endif

		/* EPIC-specific code: Soft-reset the chip ere setting as master. */
		outl(0x0001, pci_ioaddr + GENCTL);

		/* Activate the card: fix for brain-damaged Win98 BIOSes. */
		pcibios_read_config_word(pci_bus, pci_device_fn,
								 PCI_COMMAND, &pci_command);
		new_command = pci_command | PCI_COMMAND_MASTER|PCI_COMMAND_IO;
		if (pci_command != new_command) {
			printk(KERN_INFO "  The PCI BIOS has not enabled Ethernet"
				   " device %4.4x-%4.4x."
				   "  Updating PCI command %4.4x->%4.4x.\n",
				   vendor, device, pci_command, new_command);
			pcibios_write_config_word(pci_bus, pci_device_fn,
									  PCI_COMMAND, new_command);
		}

		dev = chip_tbl[chip_idx].probe1(pci_bus, pci_device_fn, dev, pci_ioaddr,
									   irq, chip_idx, cards_found);

		/* Check the latency timer. */
		if (dev) {
			u8 pci_latency;
			pcibios_read_config_byte(pci_bus, pci_device_fn,
									 PCI_LATENCY_TIMER, &pci_latency);
			if (pci_latency < chip_tbl[chip_idx].min_latency) {
				printk(KERN_INFO "  PCI latency timer (CFLT) value of %d is "
					   "unreasonably low, setting to %d.\n", pci_latency,
					   chip_tbl[chip_idx].min_latency);
				pcibios_write_config_byte(pci_bus, pci_device_fn,
										  PCI_LATENCY_TIMER,
										  chip_tbl[chip_idx].min_latency);
			}
			dev = 0;
			cards_found++;
		}
	}

	return cards_found ? 0 : -ENODEV;
}
#endif  /* not CARDBUS */

static struct net_device *epic_probe1(int pci_bus, int pci_devfn,
								  struct net_device *dev, long ioaddr, int irq,
								  int chip_idx, int card_idx)
{
	struct epic_private *ep;
	int i, option = 0, duplex = 0;

	if (dev && dev->mem_start) {
		option = dev->mem_start;
		duplex = (dev->mem_start & 16) ? 1 : 0;
	} else if (card_idx >= 0  &&  card_idx < MAX_UNITS) {
		if (options[card_idx] >= 0)
			option = options[card_idx];
		if (full_duplex[card_idx] >= 0)
			duplex = full_duplex[card_idx];
	}

	dev = init_etherdev(dev, 0);

	dev->base_addr = ioaddr;
	dev->irq = irq;
	printk(KERN_INFO "%s: %s at %#lx, IRQ %d, ",
		   dev->name, chip_tbl[chip_idx].name, ioaddr, dev->irq);

	/* Bring the chip out of low-power mode. */
	outl(0x4200, ioaddr + GENCTL);
	/* Magic?!  If we don't set this bit the MII interface won't work. */
	outl(0x0008, ioaddr + TEST1);

	/* Turn on the MII transceiver. */
	outl(0x12, ioaddr + MIICfg);
	if (chip_idx == 1)
		outl((inl(ioaddr + NVCTL) & ~0x003C) | 0x4800, ioaddr + NVCTL);
	outl(0x0200, ioaddr + GENCTL);

	/* This could also be read from the EEPROM. */
	for (i = 0; i < 3; i++)
		((u16 *)dev->dev_addr)[i] = le16_to_cpu(inw(ioaddr + LAN0 + i*4));

	for (i = 0; i < 5; i++)
		printk("%2.2x:", dev->dev_addr[i]);
	printk("%2.2x.\n", dev->dev_addr[i]);

	if (epic_debug > 2) {
		printk(KERN_DEBUG "%s: EEPROM contents\n", dev->name);
		for (i = 0; i < 64; i++)
			printk(" %4.4x%s", read_eeprom(ioaddr, i),
				   i % 16 == 15 ? "\n" : "");
	}

	/* We do a request_region() to register /proc/ioports info. */
	request_region(ioaddr, EPIC_TOTAL_SIZE, dev->name);

	/* The data structures must be quadword aligned. */
	ep = kmalloc(sizeof(*ep), GFP_KERNEL | GFP_DMA);
	memset(ep, 0, sizeof(*ep));
	dev->priv = ep;

	ep->next_module = root_epic_dev;
	root_epic_dev = dev;

	ep->pci_bus = pci_bus;
	ep->pci_dev_fn = pci_devfn;
	ep->chip_flags = chip_features[chip_idx];

	/* Find the connected MII xcvrs.
	   Doing this in open() would allow detecting external xcvrs later, but
	   takes too much time. */
	{
		int phy, phy_idx;
		for (phy = 1, phy_idx = 0; phy < 32 && phy_idx < sizeof(ep->phys);
			 phy++) {
			int mii_status = mdio_read(ioaddr, phy, 1);
			if (mii_status != 0xffff  && mii_status != 0x0000) {
				ep->phys[phy_idx++] = phy;
				printk(KERN_INFO "%s: MII transceiver #%d control "
					   "%4.4x status %4.4x.\n"
					   KERN_INFO "%s:  Autonegotiation advertising %4.4x "
					   "link partner %4.4x.\n",
					   dev->name, phy, mdio_read(ioaddr, phy, 0), mii_status,
					   dev->name, mdio_read(ioaddr, phy, 4),
					   mdio_read(ioaddr, phy, 5));
			}
		}
		ep->mii_phy_cnt = phy_idx;
		if (phy_idx == 0) {
			printk(KERN_WARNING "%s: ***WARNING***: No MII transceiver found!\n",
				   dev->name);
			/* Use the known PHY address of the EPII. */
			ep->phys[0] = 3;
		}
	}

	/* Turn off the MII xcvr (175 only!), leave the chip in low-power mode. */
	if (ep->chip_flags & MII_PWRDWN)
		outl(inl(ioaddr + NVCTL) & ~0x483C, ioaddr + NVCTL);
	outl(0x0008, ioaddr + GENCTL);

	/* The lower four bits are the media type. */
	ep->force_fd = duplex;
	dev->if_port = ep->default_port = option;
	if (ep->default_port)
		ep->medialock = 1;

	/* The Epic-specific entries in the device structure. */
	dev->open = &epic_open;
	dev->hard_start_xmit = &epic_start_xmit;
	dev->stop = &epic_close;
	dev->get_stats = &epic_get_stats;
	dev->set_multicast_list = &set_rx_mode;
	dev->do_ioctl = &mii_ioctl;
#ifdef HAVE_TX_TIMEOUT
	dev->watchdog_timeo = TX_TIMEOUT;
	dev->tx_timeout = epic_tx_timeout;
#endif

	return dev;
}

/* Serial EEPROM section. */

/*  EEPROM_Ctrl bits. */
#define EE_SHIFT_CLK	0x04	/* EEPROM shift clock. */
#define EE_CS			0x02	/* EEPROM chip select. */
#define EE_DATA_WRITE	0x08	/* EEPROM chip data in. */
#define EE_WRITE_0		0x01
#define EE_WRITE_1		0x09
#define EE_DATA_READ	0x10	/* EEPROM chip data out. */
#define EE_ENB			(0x0001 | EE_CS)

/* Delay between EEPROM clock transitions.
   No extra delay is needed with 33Mhz PCI, but 66Mhz is untested.
 */

#define eeprom_delay()	inl(ee_addr)

/* The EEPROM commands include the alway-set leading bit. */
#define EE_WRITE_CMD	(5 << 6)
#define EE_READ64_CMD	(6 << 6)
#define EE_READ256_CMD	(6 << 8)
#define EE_ERASE_CMD	(7 << 6)

static int read_eeprom(long ioaddr, int location)
{
	int i;
	int retval = 0;
	long ee_addr = ioaddr + EECTL;
	int read_cmd = location |
		(inl(ee_addr) & 0x40 ? EE_READ64_CMD : EE_READ256_CMD);

	outl(EE_ENB & ~EE_CS, ee_addr);
	outl(EE_ENB, ee_addr);

	/* Shift the read command bits out. */
	for (i = 12; i >= 0; i--) {
		short dataval = (read_cmd & (1 << i)) ? EE_WRITE_1 : EE_WRITE_0;
		outl(EE_ENB | dataval, ee_addr);
		eeprom_delay();
		outl(EE_ENB | dataval | EE_SHIFT_CLK, ee_addr);
		eeprom_delay();
	}
	outl(EE_ENB, ee_addr);

	for (i = 16; i > 0; i--) {
		outl(EE_ENB | EE_SHIFT_CLK, ee_addr);
		eeprom_delay();
		retval = (retval << 1) | ((inl(ee_addr) & EE_DATA_READ) ? 1 : 0);
		outl(EE_ENB, ee_addr);
		eeprom_delay();
	}

	/* Terminate the EEPROM access. */
	outl(EE_ENB & ~EE_CS, ee_addr);
	return retval;
}

#define MII_READOP		1
#define MII_WRITEOP		2
static int mdio_read(long ioaddr, int phy_id, int location)
{
	int i;

	outl((phy_id << 9) | (location << 4) | MII_READOP, ioaddr + MIICtrl);
	/* Typical operation takes < 50 ticks. */
	for (i = 4000; i > 0; i--)
		if ((inl(ioaddr + MIICtrl) & MII_READOP) == 0)
			return inw(ioaddr + MIIData);
	return 0xffff;
}

static void mdio_write(long ioaddr, int phy_id, int location, int value)
{
	int i;

	outw(value, ioaddr + MIIData);
	outl((phy_id << 9) | (location << 4) | MII_WRITEOP, ioaddr + MIICtrl);
	for (i = 10000; i > 0; i--) {
		if ((inl(ioaddr + MIICtrl) & MII_WRITEOP) == 0)
			break;
	}
	return;
}


static int
epic_open(struct net_device *dev)
{
	struct epic_private *ep = (struct epic_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int i;

	ep->full_duplex = ep->force_fd;

	/* Soft reset the chip. */
	outl(0x4001, ioaddr + GENCTL);

	if (request_irq(dev->irq, &epic_interrupt, SA_SHIRQ, dev->name, dev))
		return -EAGAIN;

	MOD_INC_USE_COUNT;

	epic_init_ring(dev);

	outl(0x4000, ioaddr + GENCTL);
	/* This next magic! line by Ken Yamaguchi.. ?? */
	outl(0x0008, ioaddr + TEST1);

	/* Pull the chip out of low-power mode, enable interrupts, and set for
	   PCI read multiple.  The MIIcfg setting and strange write order are
	   required by the details of which bits are reset and the transceiver
	   wiring on the Ositech CardBus card.
	*/
	outl(0x12, ioaddr + MIICfg);
	if (ep->chip_flags & MII_PWRDWN)
		outl((inl(ioaddr + NVCTL) & ~0x003C) | 0x4800, ioaddr + NVCTL);

#if defined(__powerpc__) || defined(__sparc__)		/* Big endian */
	outl(0x4432 | (RX_FIFO_THRESH<<8), ioaddr + GENCTL);
	inl(ioaddr + GENCTL);
	outl(0x0432 | (RX_FIFO_THRESH<<8), ioaddr + GENCTL);
#else
	outl(0x4412 | (RX_FIFO_THRESH<<8), ioaddr + GENCTL);
	inl(ioaddr + GENCTL);
	outl(0x0412 | (RX_FIFO_THRESH<<8), ioaddr + GENCTL);
#endif

	for (i = 0; i < 3; i++)
		outl(cpu_to_le16(((u16*)dev->dev_addr)[i]), ioaddr + LAN0 + i*4);

	
	ep->tx_threshold = TX_FIFO_THRESH;
	outl(ep->tx_threshold, ioaddr + TxThresh);

	if (media2miictl[dev->if_port & 15]) {
		if (ep->mii_phy_cnt)
			mdio_write(ioaddr, ep->phys[0], 0, media2miictl[dev->if_port&15]);
		if (dev->if_port == 1) {
			if (epic_debug > 1)
				printk(KERN_INFO "%s: Using the 10base2 transceiver, MII "
					   "status %4.4x.\n",
					   dev->name, mdio_read(ioaddr, ep->phys[0], 1));
			outl(0x13, ioaddr + MIICfg);
		}
	} else {
		int mii_reg5 = mdio_read(ioaddr, ep->phys[0], 5);
		if (mii_reg5 != 0xffff) {
			if ((mii_reg5 & 0x0100) || (mii_reg5 & 0x01C0) == 0x0040)
				ep->full_duplex = 1;
			else if (! (mii_reg5 & 0x4000))
				mdio_write(ioaddr, ep->phys[0], 0, 0x1200);
			if (epic_debug > 1)
				printk(KERN_INFO "%s: Setting %s-duplex based on MII xcvr %d"
					   " register read of %4.4x.\n", dev->name,
					   ep->full_duplex ? "full" : "half",
					   ep->phys[0], mii_reg5);
		}
	}

	outl(ep->full_duplex ? 0x7F : 0x79, ioaddr + TxCtrl);
	outl(virt_to_bus(ep->rx_ring), ioaddr + PRxCDAR);
	outl(virt_to_bus(ep->tx_ring), ioaddr + PTxCDAR);

	/* Start the chip's Rx process. */
	set_rx_mode(dev);
	outl(StartRx | RxQueued, ioaddr + COMMAND);

	netif_start_queue(dev);
	netif_mark_up(dev);

	/* Enable interrupts by setting the interrupt mask. */
	outl((ep->chip_flags & TYPE2_INTR ? PCIBusErr175 : PCIBusErr170)
		 | CntFull | TxUnderrun | TxDone | TxEmpty
		 | RxError | RxOverflow | RxFull | RxHeader | RxDone,
		 ioaddr + INTMASK);

	if (epic_debug > 1)
		printk(KERN_DEBUG "%s: epic_open() ioaddr %lx IRQ %d status %4.4x "
			   "%s-duplex.\n",
			   dev->name, ioaddr, dev->irq, inl(ioaddr + GENCTL),
			   ep->full_duplex ? "full" : "half");

	/* Set the timer to switch to check for link beat and perhaps switch
	   to an alternate media type. */
	init_timer(&ep->timer);
	ep->timer.expires = (24*HZ)/10;					/* 2.4 sec. */
	ep->timer.data = (unsigned long)dev;
	ep->timer.function = &epic_timer;				/* timer handler */
	add_timer(&ep->timer);

	return 0;
}

/* Reset the chip to recover from a PCI transaction error.
   This may occur at interrupt time. */
static void epic_pause(struct net_device *dev)
{
	long ioaddr = dev->base_addr;
	struct epic_private *ep = (struct epic_private *)dev->priv;

	netif_stop_queue(dev);

	/* Disable interrupts by clearing the interrupt mask. */
	outl(0x00000000, ioaddr + INTMASK);
	/* Stop the chip's Tx and Rx DMA processes. */
	outw(StopRx | StopTxDMA | StopRxDMA, ioaddr + COMMAND);

	/* Update the error counts. */
	if (inw(ioaddr + COMMAND) != 0xffff) {
		ep->stats.rx_missed_errors += inb(ioaddr + MPCNT);
		ep->stats.rx_frame_errors += inb(ioaddr + ALICNT);
		ep->stats.rx_crc_errors += inb(ioaddr + CRCCNT);
	}

	/* Remove the packets on the Rx queue. */
	epic_rx(dev);
}

static void epic_restart(struct net_device *dev)
{
	long ioaddr = dev->base_addr;
	struct epic_private *ep = (struct epic_private *)dev->priv;
	int i;

	printk(KERN_DEBUG "%s: Restarting the EPIC chip, Rx %d/%d Tx %d/%d.\n",
		   dev->name, ep->cur_rx, ep->dirty_rx, ep->dirty_tx, ep->cur_tx);
	/* Soft reset the chip. */
	outl(0x0001, ioaddr + GENCTL);

	udelay(1);
	/* Duplicate code from epic_open(). */
	outl(0x0008, ioaddr + TEST1);

#if defined(__powerpc__) || defined(__sparc__)		/* Big endian */
	outl(0x0432 | (RX_FIFO_THRESH<<8), ioaddr + GENCTL);
#else
	outl(0x0412 | (RX_FIFO_THRESH<<8), ioaddr + GENCTL);
#endif
	outl(dev->if_port == 1 ? 0x13 : 0x12, ioaddr + MIICfg);
	if (ep->chip_flags & MII_PWRDWN)
		outl((inl(ioaddr + NVCTL) & ~0x003C) | 0x4800, ioaddr + NVCTL);

	for (i = 0; i < 3; i++)
		outl(cpu_to_le16(((u16*)dev->dev_addr)[i]), ioaddr + LAN0 + i*4);

	ep->tx_threshold = TX_FIFO_THRESH;
	outl(ep->tx_threshold, ioaddr + TxThresh);
	outl(ep->full_duplex ? 0x7F : 0x79, ioaddr + TxCtrl);
	outl(virt_to_bus(&ep->rx_ring[ep->cur_rx%RX_RING_SIZE]), ioaddr + PRxCDAR);
	outl(virt_to_bus(&ep->tx_ring[ep->dirty_tx%TX_RING_SIZE]),
		 ioaddr + PTxCDAR);

	/* Start the chip's Rx process. */
	set_rx_mode(dev);
	outl(StartRx | RxQueued, ioaddr + COMMAND);

	/* Enable interrupts by setting the interrupt mask. */
	outl((ep->chip_flags & TYPE2_INTR ? PCIBusErr175 : PCIBusErr170)
		 | CntFull | TxUnderrun | TxDone | TxEmpty
		 | RxError | RxOverflow | RxFull | RxHeader | RxDone,
		 ioaddr + INTMASK);
	printk(KERN_DEBUG "%s: epic_restart() done, cmd status %4.4x, ctl %4.4x"
		   " interrupt %4.4x.\n",
			   dev->name, inl(ioaddr + COMMAND), inl(ioaddr + GENCTL),
		   inl(ioaddr + INTSTAT));
	return;
}

static void epic_timer(unsigned long data)
{
	struct net_device *dev = (struct net_device *)data;
	struct epic_private *ep = (struct epic_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int next_tick = 60*HZ;
	int mii_reg5 = ep->mii_phy_cnt ? mdio_read(ioaddr, ep->phys[0], 5) : 0;

	if (epic_debug > 3) {
		printk(KERN_DEBUG "%s: Media monitor tick, Tx status %8.8x.\n",
			   dev->name, inl(ioaddr + TxSTAT));
		printk(KERN_DEBUG "%s: Other registers are IntMask %4.4x "
			   "IntStatus %4.4x RxStatus %4.4x.\n",
			   dev->name, inl(ioaddr + INTMASK), inl(ioaddr + INTSTAT),
			   inl(ioaddr + RxSTAT));
	}
	if (! ep->force_fd  &&  mii_reg5 != 0xffff) {
		int duplex = (mii_reg5&0x0100) || (mii_reg5 & 0x01C0) == 0x0040;
		if (ep->full_duplex != duplex) {
			ep->full_duplex = duplex;
			printk(KERN_INFO "%s: Setting %s-duplex based on MII #%d link"
				   " partner capability of %4.4x.\n", dev->name,
				   ep->full_duplex ? "full" : "half", ep->phys[0], mii_reg5);
			outl(ep->full_duplex ? 0x7F : 0x79, ioaddr + TxCtrl);
		}
	}

	ep->timer.expires = jiffies + next_tick;
	add_timer(&ep->timer);
}

static void epic_tx_timeout(struct net_device *dev)
{
	struct epic_private *ep = (struct epic_private *)dev->priv;
	long ioaddr = dev->base_addr;

	if (epic_debug > 0) {
		printk(KERN_WARNING "%s: Transmit timeout using MII device, "
			   "Tx status %4.4x.\n",
			   dev->name, inw(ioaddr + TxSTAT));
		if (epic_debug > 1) {
			printk(KERN_DEBUG "%s: Tx indices: dirty_tx %d, cur_tx %d.\n",
				   dev->name, ep->dirty_tx, ep->cur_tx);
		}
	}
	if (inw(ioaddr + TxSTAT) & 0x10) {		/* Tx FIFO underflow. */
		ep->stats.tx_fifo_errors++;
		outl(RestartTx, ioaddr + COMMAND);
	} else {
		epic_restart(dev);
		outl(TxQueued, dev->base_addr + COMMAND);
	}

	dev->trans_start = jiffies;
	ep->stats.tx_errors++;
	return;
}

/* Initialize the Rx and Tx rings, along with various 'dev' bits. */
static void
epic_init_ring(struct net_device *dev)
{
	struct epic_private *ep = (struct epic_private *)dev->priv;
	int i;

	ep->tx_full = 0;
	ep->lock = (spinlock_t) SPIN_LOCK_UNLOCKED;
	ep->dirty_tx = ep->cur_tx = 0;
	ep->cur_rx = ep->dirty_rx = 0;
	ep->last_rx_time = jiffies;

	for (i = 0; i < RX_RING_SIZE; i++) {
		ep->rx_ring[i].status = 0x8000;		/* Owned by Epic chip */
		ep->rx_ring[i].buflength = PKT_BUF_SZ;
		{
			/* Note the receive buffer must be longword aligned.
			   dev_alloc_skb() provides 16 byte alignment.  But do *not*
			   use skb_reserve() to align the IP header! */
			struct sk_buff *skb;
			skb = dev_alloc_skb(PKT_BUF_SZ);
			ep->rx_skbuff[i] = skb;
			if (skb == NULL)
				break;			/* Bad news!  */
			skb->dev = dev;			/* Mark as being used by this device. */
			skb_reserve(skb, 2); /* Align IP on 16 byte boundaries */
			ep->rx_ring[i].bufaddr = virt_to_bus(skb->tail);
		}
		ep->rx_ring[i].next = virt_to_bus(&ep->rx_ring[i+1]);
	}
	/* Mark the last entry as wrapping the ring. */
	ep->rx_ring[i-1].next = virt_to_bus(&ep->rx_ring[0]);

	/* The Tx buffer descriptor is filled in as needed, but we
	   do need to clear the ownership bit. */
	for (i = 0; i < TX_RING_SIZE; i++) {
		ep->tx_skbuff[i] = 0;
		ep->tx_ring[i].status = 0x0000;
		ep->tx_ring[i].next = virt_to_bus(&ep->tx_ring[i+1]);
	}
	ep->tx_ring[i-1].next = virt_to_bus(&ep->tx_ring[0]);
}

static int
epic_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct epic_private *ep = (struct epic_private *)dev->priv;
	int entry, free_count;
	u32 ctrl_word;
	long flags;

	tx_timeout_check(dev, epic_tx_timeout);

	/* Caution: the write order is important here, set the base address
	   with the "ownership" bits last. */

	/* Calculate the next Tx descriptor entry. */
	spin_lock_irqsave(&ep->lock, flags);
	free_count = ep->cur_tx - ep->dirty_tx;
	entry = ep->cur_tx++ % TX_RING_SIZE;

	ep->tx_skbuff[entry] = skb;
	ep->tx_ring[entry].txlength = (skb->len >= ETH_ZLEN ? skb->len : ETH_ZLEN);
	ep->tx_ring[entry].bufaddr = virt_to_bus(skb->data);
	ep->tx_ring[entry].buflength = skb->len;

	if (free_count < TX_RING_SIZE/2) {/* Typical path */
		ctrl_word = 0x10; /* No interrupt */
	} else if (free_count == TX_RING_SIZE/2) {
		ctrl_word = 0x14; /* Tx-done intr. */
	} else if (free_count < TX_RING_SIZE - 1) {
		ctrl_word = 0x10; /* No Tx-done intr. */
	} else {
		/* Leave room for an additional entry. */
		ctrl_word = 0x14; /* Tx-done intr. */
		ep->tx_full = 1;
	}

	ep->tx_ring[entry].control = ctrl_word;
	ep->tx_ring[entry].status = 0x8000;	/* Pass ownership to the chip. */

	if ( ! ep->tx_full)
		netif_start_queue(dev);
	spin_unlock_irqrestore(&ep->lock, flags);
	/* Trigger an immediate transmit demand. */
	outl(TxQueued, dev->base_addr + COMMAND);

	dev->trans_start = jiffies;
	if (epic_debug > 4)
		printk(KERN_DEBUG "%s: Queued Tx packet size %d to slot %d, "
			   "flag %2.2x Tx status %8.8x.\n",
			   dev->name, (int)skb->len, entry, ctrl_word,
			   inl(dev->base_addr + TxSTAT));

	return 0;
}

/* The interrupt handler does all of the Rx thread work and cleans up
   after the Tx thread. */
static void epic_interrupt(int irq, void *dev_instance, struct pt_regs *regs)
{
	struct net_device *dev = (struct net_device *)dev_instance;
	struct epic_private *ep = (struct epic_private *)dev->priv;
	long ioaddr = dev->base_addr;
	int status, boguscnt = max_interrupt_work;

	do {
		status = inl(ioaddr + INTSTAT);
		/* Acknowledge all of the current interrupt sources ASAP. */
		outl(status & 0x00007fff, ioaddr + INTSTAT);

		if (epic_debug > 4)
			printk(KERN_DEBUG "%s: interrupt  interrupt=%#8.8x new "
				   "intstat=%#8.8x.\n",
				   dev->name, status, inl(ioaddr + INTSTAT));

		if ((status & IntrSummary) == 0)
			break;

		if (status & (RxDone | RxStarted | RxEarlyWarn | RxOverflow))
			epic_rx(dev);

		if (status & (TxEmpty | TxDone)) {
			unsigned int dirty_tx, cur_tx;

			/* Note: if this lock becomes a problem we can narrow the locked
			   region at the cost of occasionally grabbing the lock more
			   times. */
			spin_lock(&ep->lock);
			cur_tx = ep->cur_tx;
			dirty_tx = ep->dirty_tx;
			for (; cur_tx - dirty_tx > 0; dirty_tx++) {
				int entry = dirty_tx % TX_RING_SIZE;
				int txstatus = ep->tx_ring[entry].status;

				if (txstatus < 0)
					break;			/* It still hasn't been Txed */

				if ( ! (txstatus & 0x0001)) {
					/* There was an major error, log it. */
#ifndef final_version
					if (epic_debug > 1)
						printk("%s: Transmit error, Tx status %8.8x.\n",
							   dev->name, txstatus);
#endif
					ep->stats.tx_errors++;
					if (txstatus & 0x1050) ep->stats.tx_aborted_errors++;
					if (txstatus & 0x0008) ep->stats.tx_carrier_errors++;
					if (txstatus & 0x0040) ep->stats.tx_window_errors++;
					if (txstatus & 0x0010) ep->stats.tx_fifo_errors++;
#ifdef ETHER_STATS
					if (txstatus & 0x1000) ep->stats.collisions16++;
#endif
				} else {
#ifdef ETHER_STATS
					if ((txstatus & 0x0002) != 0) ep->stats.tx_deferred++;
#endif
					ep->stats.collisions += (txstatus >> 8) & 15;
					ep->stats.tx_packets++;
					add_tx_bytes(&ep->stats, ep->tx_ring[entry].txlength);
				}

				/* Free the original skb. */
				dev_kfree_skb_irq(ep->tx_skbuff[entry]);
				ep->tx_skbuff[entry] = 0;
			}

#ifndef final_version
			if (cur_tx - dirty_tx > TX_RING_SIZE) {
				printk("%s: Out-of-sync dirty pointer, %d vs. %d, full=%d.\n",
					   dev->name, dirty_tx, cur_tx, ep->tx_full);
				dirty_tx += TX_RING_SIZE;
			}
#endif
			ep->dirty_tx = dirty_tx;
			if (ep->tx_full
				&& cur_tx - dirty_tx < TX_RING_SIZE + 2) {
				/* The ring is no longer full, clear tbusy. */
				ep->tx_full = 0;
				spin_unlock(&ep->lock);
				netif_wake_queue(dev);
			} else
				spin_unlock(&ep->lock);
		}

		/* Check uncommon events all at once. */
		if (status & (CntFull | TxUnderrun | RxOverflow | RxFull |
					  PCIBusErr170 | PCIBusErr175)) {
			if (status == 0xffffffff) /* Chip failed or removed (CardBus). */
				break;
			/* Always update the error counts to avoid overhead later. */
			ep->stats.rx_missed_errors += inb(ioaddr + MPCNT);
			ep->stats.rx_frame_errors += inb(ioaddr + ALICNT);
			ep->stats.rx_crc_errors += inb(ioaddr + CRCCNT);

			if (status & TxUnderrun) { /* Tx FIFO underflow. */
				ep->stats.tx_fifo_errors++;
				outl(ep->tx_threshold += 128, ioaddr + TxThresh);
				/* Restart the transmit process. */
				outl(RestartTx, ioaddr + COMMAND);
			}
			if (status & RxOverflow) {		/* Missed a Rx frame. */
				ep->stats.rx_errors++;
			}
			if (status & (RxOverflow | RxFull))
				outw(RxQueued, ioaddr + COMMAND);
			if (status & PCIBusErr170) {
				printk(KERN_ERR "%s: PCI Bus Error!  EPIC status %4.4x.\n",
					   dev->name, status);
				epic_pause(dev);
				epic_restart(dev);
			}
			/* Clear all error sources. */
			outl(status & 0x7f18, ioaddr + INTSTAT);
		}
		if (--boguscnt < 0) {
			printk(KERN_ERR "%s: Too much work at interrupt, "
				   "IntrStatus=0x%8.8x.\n",
				   dev->name, status);
			/* Clear all interrupt sources. */
			outl(0x0001ffff, ioaddr + INTSTAT);
			break;
		}
	} while (1);

	if (epic_debug > 3)
		printk(KERN_DEBUG "%s: exiting interrupt, intr_status=%#4.4x.\n",
			   dev->name, inl(ioaddr + INTSTAT));

	return;
}

static int epic_rx(struct net_device *dev)
{
	struct epic_private *ep = (struct epic_private *)dev->priv;
	int entry = ep->cur_rx % RX_RING_SIZE;
	int rx_work_limit = ep->dirty_rx + RX_RING_SIZE - ep->cur_rx;
	int work_done = 0;

	if (epic_debug > 4)
		printk(KERN_DEBUG " In epic_rx(), entry %d %8.8x.\n", entry,
			   ep->rx_ring[entry].status);
	/* If we own the next entry, it's a new packet. Send it up. */
	while (ep->rx_ring[entry].status >= 0) {
		int status = ep->rx_ring[entry].status;

		if (epic_debug > 4)
			printk(KERN_DEBUG "  epic_rx() status was %8.8x.\n", status);
		if (--rx_work_limit < 0)
			break;
		if (status & 0x2006) {
			if (status & 0x2000) {
				printk(KERN_WARNING "%s: Oversized Ethernet frame spanned "
					   "multiple buffers, status %4.4x!\n", dev->name, status);
				ep->stats.rx_length_errors++;
			} else if (status & 0x0006)
				/* Rx Frame errors are counted in hardware. */
				ep->stats.rx_errors++;
		} else {
			/* Malloc up new buffer, compatible with net-2e. */
			/* Omit the four octet CRC from the length. */
			short pkt_len = ep->rx_ring[entry].rxlength - 4;
			struct sk_buff *skb;

			if (pkt_len > PKT_BUF_SZ - 4) {
				printk(KERN_ERR "%s: Oversized Ethernet frame, status %x "
					   "%d bytes.\n",
					   dev->name, pkt_len, status);
				pkt_len = 1514;
			}
			/* Check if the packet is long enough to accept without copying
			   to a minimally-sized skbuff. */
			if (pkt_len < rx_copybreak
				&& (skb = dev_alloc_skb(pkt_len + 2)) != NULL) {
				skb->dev = dev;
				skb_reserve(skb, 2);	/* 16 byte align the IP header */
#if 1 /* USE_IP_COPYSUM */
				eth_copy_and_sum(skb, bus_to_virt(ep->rx_ring[entry].bufaddr),
								 pkt_len, 0);
				skb_put(skb, pkt_len);
#else
				memcpy(skb_put(skb, pkt_len),
					   bus_to_virt(ep->rx_ring[entry].bufaddr), pkt_len);
#endif
			} else {
				skb_put(skb = ep->rx_skbuff[entry], pkt_len);
				ep->rx_skbuff[entry] = NULL;
			}
			skb->protocol = eth_type_trans(skb, dev);
			netif_rx(skb);
			ep->stats.rx_packets++;
			add_rx_bytes(&ep->stats, pkt_len);
		}
		work_done++;
		entry = (++ep->cur_rx) % RX_RING_SIZE;
	}

	/* Refill the Rx ring buffers. */
	for (; ep->cur_rx - ep->dirty_rx > 0; ep->dirty_rx++) {
		entry = ep->dirty_rx % RX_RING_SIZE;
		if (ep->rx_skbuff[entry] == NULL) {
			struct sk_buff *skb;
			skb = ep->rx_skbuff[entry] = dev_alloc_skb(PKT_BUF_SZ);
			if (skb == NULL)
				break;
			skb->dev = dev;			/* Mark as being used by this device. */
			skb_reserve(skb, 2);	/* Align IP on 16 byte boundaries */
			ep->rx_ring[entry].bufaddr = virt_to_bus(skb->tail);
			work_done++;
		}
		ep->rx_ring[entry].status = 0x8000;
	}
	return work_done;
}

static int epic_close(struct net_device *dev)
{
	long ioaddr = dev->base_addr;
	struct epic_private *ep = (struct epic_private *)dev->priv;
	int i;

	netif_stop_queue(dev);
	netif_mark_down(dev);

	if (epic_debug > 1)
		printk(KERN_DEBUG "%s: Shutting down ethercard, status was %2.2x.\n",
			   dev->name, inl(ioaddr + INTSTAT));

	epic_pause(dev);
	del_timer(&ep->timer);
	/* Disable interrupts by clearing the interrupt mask. */
	outl(0, ioaddr + INTMASK);
	free_irq(dev->irq, dev);

	/* Free all the skbuffs in the Rx queue. */
	for (i = 0; i < RX_RING_SIZE; i++) {
		struct sk_buff *skb = ep->rx_skbuff[i];
		ep->rx_skbuff[i] = 0;
		ep->rx_ring[i].status = 0;		/* Not owned by Epic chip. */
		ep->rx_ring[i].buflength = 0;
		ep->rx_ring[i].bufaddr = 0xBADF00D0; /* An invalid address. */
		if (skb) {
#if LINUX_VERSION_CODE < 0x20100
			skb->free = 1;
#endif
			dev_free_skb(skb);
		}
	}
	for (i = 0; i < TX_RING_SIZE; i++) {
		if (ep->tx_skbuff[i])
			dev_free_skb(ep->tx_skbuff[i]);
		ep->tx_skbuff[i] = 0;
	}

	/* Green! Leave the chip in low-power mode. */
	outl(0x0008, ioaddr + GENCTL);

	MOD_DEC_USE_COUNT;
	return 0;
}

static struct net_device_stats *epic_get_stats(struct net_device *dev)
{
	struct epic_private *ep = (struct epic_private *)dev->priv;
	long ioaddr = dev->base_addr;

	if (netif_running(dev)) {
		/* Update the error counts. */
		ep->stats.rx_missed_errors += inb(ioaddr + MPCNT);
		ep->stats.rx_frame_errors += inb(ioaddr + ALICNT);
		ep->stats.rx_crc_errors += inb(ioaddr + CRCCNT);
	}

	return &ep->stats;
}

/* Set or clear the multicast filter for this adaptor.
   Note that we only use exclusion around actually queueing the
   new frame, not around filling ep->setup_frame.  This is non-deterministic
   when re-entered but still correct. */

/* The little-endian AUTODIN II ethernet CRC calculation.
   N.B. Do not use for bulk data, use a table-based routine instead.
   This is common code and should be moved to net/core/crc.c */
static unsigned const ethernet_polynomial_le = 0xedb88320U;
static inline unsigned ether_crc_le(int length, unsigned char *data)
{
	unsigned int crc = 0xffffffff;	/* Initial value. */
	while(--length >= 0) {
		unsigned char current_octet = *data++;
		int bit;
		for (bit = 8; --bit >= 0; current_octet >>= 1) {
			if ((crc ^ current_octet) & 1) {
				crc >>= 1;
				crc ^= ethernet_polynomial_le;
			} else
				crc >>= 1;
		}
	}
	return crc;
}


static void set_rx_mode(struct net_device *dev)
{
	long ioaddr = dev->base_addr;
	struct epic_private *ep = (struct epic_private *)dev->priv;
	unsigned char mc_filter[8];		 /* Multicast hash filter */
	int i;

	if (dev->flags & IFF_PROMISC) {			/* Set promiscuous. */
		outl(0x002C, ioaddr + RxCtrl);
		/* Unconditionally log net taps. */
		printk(KERN_INFO "%s: Promiscuous mode enabled.\n", dev->name);
		memset(mc_filter, 0xff, sizeof(mc_filter));
	} else if ((dev->mc_count > 0)  ||  (dev->flags & IFF_ALLMULTI)) {
		/* There is apparently a chip bug, so the multicast filter
		   is never enabled. */
		/* Too many to filter perfectly -- accept all multicasts. */
		memset(mc_filter, 0xff, sizeof(mc_filter));
		outl(0x000C, ioaddr + RxCtrl);
	} else if (dev->mc_count == 0) {
		outl(0x0004, ioaddr + RxCtrl);
		return;
	} else {					/* Never executed, for now. */
		struct dev_mc_list *mclist;

		memset(mc_filter, 0, sizeof(mc_filter));
		for (i = 0, mclist = dev->mc_list; mclist && i < dev->mc_count;
			 i++, mclist = mclist->next)
			set_bit(ether_crc_le(ETH_ALEN, mclist->dmi_addr) & 0x3f,
					mc_filter);
	}
	/* ToDo: perhaps we need to stop the Tx and Rx process here? */
	if (memcmp(mc_filter, ep->mc_filter, sizeof(mc_filter))) {
		for (i = 0; i < 4; i++)
			outw(((u16 *)mc_filter)[i], ioaddr + MC0 + i*4);
		memcpy(ep->mc_filter, mc_filter, sizeof(mc_filter));
	}
	return;
}

static int mii_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	long ioaddr = dev->base_addr;
	u16 *data = (u16 *)&rq->ifr_data;

	switch(cmd) {
	case SIOCDEVPRIVATE:		/* Get the address of the PHY in use. */
		data[0] = ((struct epic_private *)dev->priv)->phys[0] & 0x1f;
		/* Fall Through */
	case SIOCDEVPRIVATE+1:		/* Read the specified MII register. */
		if (! netif_running(dev)) {
			outl(0x0200, ioaddr + GENCTL);
			outl((inl(ioaddr + NVCTL) & ~0x003C) | 0x4800, ioaddr + NVCTL);
		}
		data[3] = mdio_read(ioaddr, data[0] & 0x1f, data[1] & 0x1f);
		if (! netif_running(dev)) {
#ifdef notdef					/* Leave on if the ioctl() is used. */
			outl(0x0008, ioaddr + GENCTL);
			outl((inl(ioaddr + NVCTL) & ~0x483C) | 0x0000, ioaddr + NVCTL);
#endif
		}
		return 0;
	case SIOCDEVPRIVATE+2:		/* Write the specified MII register */
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (! netif_running(dev)) {
			outl(0x0200, ioaddr + GENCTL);
			outl((inl(ioaddr + NVCTL) & ~0x003C) | 0x4800, ioaddr + NVCTL);
		}
		mdio_write(ioaddr, data[0] & 0x1f, data[1] & 0x1f, data[2]);
		if (! netif_running(dev)) {
#ifdef notdef					/* Leave on if the ioctl() is used. */
			outl(0x0008, ioaddr + GENCTL);
			outl((inl(ioaddr + NVCTL) & ~0x483C) | 0x0000, ioaddr + NVCTL);
#endif
		}
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}


#ifdef CARDBUS

#include <pcmcia/driver_ops.h>

static dev_node_t *epic_attach(dev_locator_t *loc)
{
	struct net_device *dev;
	u16 dev_id;
	u32 io;
	u8 bus, devfn, irq;

	if (loc->bus != LOC_PCI) return NULL;
	bus = loc->b.pci.bus; devfn = loc->b.pci.devfn;
	printk(KERN_DEBUG "epic_attach(bus %d, function %d)\n", bus, devfn);
	pcibios_read_config_dword(bus, devfn, PCI_BASE_ADDRESS_0, &io);
	pcibios_read_config_byte(bus, devfn, PCI_INTERRUPT_LINE, &irq);
	pcibios_read_config_word(bus, devfn, PCI_DEVICE_ID, &dev_id);
	io &= ~3;
	if (io == 0 || irq == 0) {
		printk(KERN_ERR "The EPIC/C CardBus Ethernet interface was not "
			   "assigned an %s.\n" KERN_ERR "  It will not be activated.\n",
			   io == 0 ? "I/O address" : "IRQ");
		return NULL;
	}
	dev = epic_probe1(bus, devfn, NULL, io, irq, 1, -1);
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

static void epic_suspend(dev_node_t *node)
{
	struct net_device **devp, **next;
	printk(KERN_INFO "epic_suspend(%s)\n", node->dev_name);
	for (devp = &root_epic_dev; *devp; devp = next) {
		next = &((struct epic_private *)(*devp)->priv)->next_module;
		if (strcmp((*devp)->name, node->dev_name) == 0) break;
	}
	if (*devp) {
		long ioaddr = (*devp)->base_addr;
		epic_pause(*devp);
		/* Put the chip into low-power mode. */
		outl(0x0008, ioaddr + GENCTL);
	}
}
static void epic_resume(dev_node_t *node)
{
	struct net_device **devp, **next;
	printk(KERN_INFO "epic_resume(%s)\n", node->dev_name);
	for (devp = &root_epic_dev; *devp; devp = next) {
		next = &((struct epic_private *)(*devp)->priv)->next_module;
		if (strcmp((*devp)->name, node->dev_name) == 0) break;
	}
	if (*devp) {
		epic_restart(*devp);
	}
}
static void epic_detach(dev_node_t *node)
{
	struct net_device **devp, **next;
	printk(KERN_INFO "epic_detach(%s)\n", node->dev_name);
	for (devp = &root_epic_dev; *devp; devp = next) {
		next = &((struct epic_private *)(*devp)->priv)->next_module;
		if (strcmp((*devp)->name, node->dev_name) == 0) break;
	}
	if (*devp) {
		unregister_netdev(*devp);
		kfree(*devp);
		*devp = *next;
		kfree(node);
		MOD_DEC_USE_COUNT;
	}
}

struct driver_operations epic_ops = {
	"epic_cb", epic_attach, epic_suspend, epic_resume, epic_detach
};

#endif  /* Cardbus support */


#ifdef MODULE

int init_module(void)
{
	if (epic_debug)
		printk(KERN_INFO "%s", version);

#ifdef CARDBUS
	register_driver(&epic_ops);
	return 0;
#else
	return epic100_probe(0);
#endif
}

void cleanup_module(void)
{
	struct net_device *next_dev;

#ifdef CARDBUS
	unregister_driver(&epic_ops);
#endif

	/* No need to check MOD_IN_USE, as sys_delete_module() checks. */
	while (root_epic_dev) {
		struct epic_private *ep = (struct epic_private *)root_epic_dev->priv;
		next_dev = ep->next_module;
		unregister_netdev(root_epic_dev);
#ifdef EPIC_USE_IO
		release_region(root_epic_dev->base_addr, EPIC_TOTAL_SIZE);
#else
		iounmap((char *)root_epic_dev->base_addr);
#endif
		kfree(root_epic_dev);
		root_epic_dev = next_dev;
		kfree(ep);
	}
}

#endif  /* MODULE */

/*
 * Local variables:
 *  compile-command: "gcc -DMODULE -D__KERNEL__ -Wall -Wstrict-prototypes -O6 -c epic100.c `[ -f /usr/include/linux/modversions.h ] && echo -DMODVERSIONS`"
 *  cardbus-compile-command: "gcc -DCARDBUS -DMODULE -D__KERNEL__ -Wall -Wstrict-prototypes -O6 -c epic100.c -o epic_cb.o -I/usr/src/pcmcia-cs-3.0.13/include/"
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
