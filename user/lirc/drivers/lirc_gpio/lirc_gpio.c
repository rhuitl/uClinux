/*
 * Remote control driver for the TV-card
 * key codes are obtained from GPIO port
 * 
 * (L) by Artur Lipowski <alipowski@kki.net.pl>
 *     patch for the AverMedia by Santiago Garcia Mantinan <manty@i.am>
 *                            and Christoph Bartelmus <lirc@bartelmus.de>
 *     patch for the BestBuy by Miguel Angel Alvarez <maacruz@navegalia.com>
 * This code is licensed under GNU GPL
 *
 * $Id: lirc_gpio.c,v 1.7 2001/01/21 11:10:39 columbus Exp $
 *
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 2, 4)
#error "*******************************************************"
#error "Sorry, this driver needs kernel version 2.2.4 or higher"
#error "*******************************************************"
#endif

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/wrapper.h>
#include <linux/errno.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
/* comes with bttv */
#include "../drivers/char/kcompat24.h"

#include "../drivers/char/bttv.h"
#include "../drivers/char/bttvp.h"
#else
#include "../drivers/media/video/bttv.h"
#include "../drivers/media/video/bttvp.h"
#endif

#if BTTV_VERSION_CODE < KERNEL_VERSION(0,7,45)
#error "*******************************************************"
#error " Sorry, this driver needs bttv version 0.7.45 or       "
#error " higher. If you are using the bttv package, copy it to "
#error " the kernel                                            "
#error "*******************************************************"
#endif

#include "../lirc_dev/lirc_dev.h"

static int debug = 0;
static int card = 0;
static int minor = -1;
static unsigned long gpio_mask = 0;
static unsigned long gpio_enable = 0;
static unsigned long gpio_lock_mask = 0;
static unsigned long gpio_xor_mask = 0;
static unsigned int soft_gap = 0;
static unsigned char sample_rate = 10;

MODULE_PARM(debug,"i");
MODULE_PARM(card,"i");
MODULE_PARM(minor,"i");
MODULE_PARM(gpio_mask,"l");
MODULE_PARM(gpio_lock_mask,"l");
MODULE_PARM(gpio_xor_mask,"l");
MODULE_PARM(soft_gap,"i");
MODULE_PARM(sample_rate,"b");

#define dprintk  if (debug) printk

struct rcv_info {
	int bttv_id;
	int card_id;
	unsigned long gpio_mask;
	unsigned long gpio_enable;
	unsigned long gpio_lock_mask;
	unsigned long gpio_xor_mask;
	unsigned int soft_gap;
	unsigned char sample_rate;
	unsigned char code_length;
};

static struct rcv_info rcv_infos[] = {
	{BTTV_UNKNOWN,                0,          0,          0,         0,          0,   0,  1,  0},
#ifdef BTTV_PXELVWPLTVPAK
	{BTTV_PXELVWPLTVPAK,          0, 0x00003e00,          0, 0x0010000,          0,   0, 15,  0},
#endif
	{BTTV_PXELVWPLTVPRO,          0, 0x00001f00,          0, 0x0008000,          0, 500, 12,  0},
	{BTTV_AVERMEDIA,              0, 0x00f88000,          0, 0x0010000, 0x00010000,   0, 10, 32},
	{BTTV_AVPHONE98,     0x00011461, 0x003b8000, 0x00004000, 0x0800000, 0x00800000,   0, 10,  0}, /*mapped to Capture98*/
	{BTTV_AVERMEDIA98,   0x00021461, 0x003b8000, 0x00004000, 0x0800000, 0x00800000,   0, 10,  0}, /*mapped to Capture98*/
	{BTTV_AVPHONE98,     0x00031461, 0x00f88000,          0, 0x0010000, 0x00010000,   0, 10, 32}, /*mapped to Phone98*/
	/* is this one correct? */
	{BTTV_AVERMEDIA98,   0x00041461, 0x00f88000,          0, 0x0010000, 0x00010000,   0, 10, 32}, /*mapped to Phone98*/
	{BTTV_CHRONOS_VS2,            0, 0x000000f8,          0, 0x0000100,          0,   0, 20,  0},
	/* CPH031 and CPH033 cards (?) */
	/* MIRO was just a work-around */
	{BTTV_MIRO,                   0, 0x00001f00,          0, 0x0004000,          0,   0, 10, 32},
	{BTTV_DYNALINK,               0, 0x00001f00,          0, 0x0004000,          0,   0, 10, 32},
	/* just a guess */
	{BTTV_MAGICTVIEW061,          0, 0x0028e000,          0, 0x0020000,          0,   0, 20, 32},
 	{BTTV_MAGICTVIEW063,          0, 0x0028e000,          0, 0x0020000,          0,   0, 20, 32},
 	{BTTV_PHOEBE_TVMAS,           0, 0x0028e000,          0, 0x0020000,          0,   0, 20, 32},
#ifdef BTTV_BESTBUY
        {BTTV_BESTBUY,                0, 0x00007F00,          0, 0x0004000,          0,   0, 10,  8},
#endif
 	{BTTV_FLYVIDEO_98,            0, 0x000001f8,          0, 0x0000100,          0,   0,  0,  0}
};

static unsigned char code_length = 0;
static unsigned char code_bytes = 1;
static int card_type = 0;

#define MAX_BYTES 8

#define SUCCESS 0
#define LOGHEAD "lirc_gpio (%d): "

/* how many bits GPIO value can be shifted right before processing
 * it is computed from the value of gpio_mask_parameter
 */
static unsigned char gpio_pre_shift = 0;


static inline int reverse(int data, int bits)
{
	int i;
	int c;
	
	for (c=0,i=0; i<bits; i++) {
		c |= (((data & (1<<i)) ? 1:0)) << (bits-1-i);
	}

	return c;
}

static int build_key(unsigned long gpio_val, unsigned char codes[MAX_BYTES])
{
	unsigned long mask = gpio_mask;
	unsigned char shift = 0;

	dprintk(LOGHEAD "gpio_val is %lx\n",card,(unsigned long) gpio_val);
	
	gpio_val ^= gpio_xor_mask;
	
	if (gpio_lock_mask && (gpio_val & gpio_lock_mask)) {
		return -EBUSY;
	}

	switch (rcv_infos[card_type].bttv_id)
	{
	case BTTV_AVERMEDIA98:
		if (bttv_write_gpio(card, gpio_enable, gpio_enable)) {
			dprintk(LOGHEAD "cannot write to GPIO\n", card);
			return -EIO;
		}
		if (bttv_read_gpio(card, &gpio_val)) {
			dprintk(LOGHEAD "cannot read GPIO\n", card);
			return -EIO;
		}
		if (bttv_write_gpio(card, gpio_enable, 0)) {
			dprintk(LOGHEAD "cannot write to GPIO\n", card);
			return -EIO;
		}
		break;
	default:
		break;
	}
	
	/* extract bits from "raw" GPIO value using gpio_mask */
	codes[0] = 0;
	gpio_val >>= gpio_pre_shift;
	while (mask) {
		if (mask & 1u) {
			codes[0] |= (gpio_val & 1u) << shift++;
		}
		mask >>= 1;
		gpio_val >>= 1;
	}
	
	dprintk(LOGHEAD "code is %lx\n",card,(unsigned long) codes[0]);
	switch (rcv_infos[card_type].bttv_id)
	{
	case BTTV_AVERMEDIA:
		codes[2] = (codes[0]<<2)&0xff;
		codes[3] = (~codes[2])&0xff;
		codes[0] = 0x02;
		codes[1] = 0xFD;
		break;
	case BTTV_AVPHONE98:
		codes[2] = ((codes[0]&(~0x1))<<2)&0xff;
		codes[3] = (~codes[2])&0xff;
		if (codes[0]&0x1) {
			codes[0] = 0xc0;
			codes[1] = 0x3f;
		} else {
			codes[0] = 0x40;
			codes[1] = 0xbf;
		}
		break;
	case BTTV_AVERMEDIA98:
		break;
        case BTTV_MAGICTVIEW061:
        case BTTV_MAGICTVIEW063:
	case BTTV_PHOEBE_TVMAS:
		codes[0] = (codes[0]&0x01)
			|((codes[0]&0x02)<<1)
			|((codes[0]&0x04)<<2)
			|((codes[0]&0x08)>>2)
			|((codes[0]&0x10)>>1);
		/* FALLTHROUGH */
	case BTTV_MIRO:
	case BTTV_DYNALINK:
		codes[2] = reverse(codes[0],8);
		codes[3] = (~codes[2])&0xff;
		codes[0] = 0x61;
		codes[1] = 0xD6;
		break;
	default:
		break;
	}

	return SUCCESS;
}

static int get_key(void* data, unsigned char *key, int key_no)
{
	static unsigned long next_time = 0;
	static unsigned char codes[MAX_BYTES];
	unsigned long code = 0;
	unsigned char cur_codes[MAX_BYTES];
	
	if (key_no > 0)	{
		if (code_bytes < 2 || key_no >= code_bytes) {
			dprintk(LOGHEAD "something wrong in get_key\n", card);
			return -EBADRQC;
		}
		*key = codes[key_no];
		return SUCCESS;
	}
	
	if (bttv_read_gpio(card, &code)) {
		dprintk(LOGHEAD "cannot read GPIO\n", card);
		return -EIO;
	}

	if (build_key(code, cur_codes)) {
		return -EFAULT;
	}

	if (soft_gap) {
		if (!memcmp(codes, cur_codes, code_bytes) && 
		    jiffies < next_time) {
			return -EAGAIN;
		}
		next_time = jiffies + soft_gap;
	}

	memcpy(codes, cur_codes, code_bytes);

	*key = codes[0];

	return SUCCESS;
}

static void set_use_inc(void* data)
{
	MOD_INC_USE_COUNT;
}

static void set_use_dec(void* data)
{
	MOD_DEC_USE_COUNT;
}

static wait_queue_head_t* get_queue(void* data)
{
	return bttv_get_gpio_queue(card);
}

static struct lirc_plugin plugin = {
	"lirc_gpio  ",
	0,
	0,
	0,
	NULL,
	get_key,
	get_queue,
	set_use_inc,
	set_use_dec
};

/*
 *
 */
int gpio_remote_init(void)
{  	
	int ret;
	unsigned int mask;

	/* "normalize" gpio_mask
	 * this means shift it right until first bit is set
	 */
	while (!(gpio_mask & 1u)) {
		gpio_pre_shift++;
		gpio_mask >>= 1;
	}

	if (code_length) {
		plugin.code_length = code_length;
	} else {
		/* calculate scan code length in bits if needed */
		plugin.code_length = 1;
		mask = gpio_mask >> 1;
		while (mask) {
			if (mask & 1u) {
				plugin.code_length++;
			}
			mask >>= 1;
		}
	}

	code_bytes = (plugin.code_length/8) + (plugin.code_length%8 ? 1 : 0);
	if (MAX_BYTES < code_bytes) {
		printk (LOGHEAD "scan code too long (%d bytes)\n",
			minor, code_bytes);
		return -EBADRQC;
	}

	if (gpio_enable) {
		if(bttv_gpio_enable(card, gpio_enable, gpio_enable)) {
			printk(LOGHEAD "gpio_enable failure\n", minor);
			return -EIO;
		}
	}


	/* translate ms to jiffies */
	soft_gap = (soft_gap*HZ) / 1000;

	plugin.minor = minor;
	plugin.sample_rate = sample_rate;

	ret = lirc_register_plugin(&plugin);
	
	if (0 > ret) {
		printk (LOGHEAD "device registration failed with %d\n",
			minor, ret);
		return ret;
	}
	
	minor = ret;
	printk(LOGHEAD "driver registered\n", minor);

	return SUCCESS;
}

EXPORT_NO_SYMBOLS; 

/* Dont try to use it as a static version !  */

#ifdef MODULE
MODULE_DESCRIPTION("Driver module for remote control (data from bt848 GPIO port)");
MODULE_AUTHOR("Artur Lipowski");

/*
 *
 */
int init_module(void)
{
	int type,cardid;

	if (MAX_IRCTL_DEVICES < minor) {
		printk("lirc_gpio: parameter minor (%d) must be less than %d!\n",
		       minor, MAX_IRCTL_DEVICES-1);
		return -EBADRQC;
	}
	
	request_module("bttv");

	/* if gpio_mask not zero then use module parameters 
	 * instead of autodetecting TV card
	 */
	if (gpio_mask) {
		if (2 > sample_rate || 50 < sample_rate) {
			printk(LOGHEAD "parameter sample_rate "
			       "must be beetween 2 and 50!\n", minor);
			return -EBADRQC;
		}

		if (soft_gap && 
		    ((2000/sample_rate) > soft_gap || 1000 < soft_gap)) {
			printk(LOGHEAD "parameter soft_gap "
			       "must be beetween %d and 1000!\n",
			       minor, 2000/sample_rate);
			return -EBADRQC;
		}
	} else {
		if(bttv_get_cardinfo(card,&type,&cardid)==-1) {
			printk(LOGHEAD "could not get card type\n", minor);
		}
		printk(LOGHEAD "card type 0x%x, id 0x%x\n",minor,
		       type,cardid);

		if (type == BTTV_UNKNOWN) {
			printk(LOGHEAD "cannot detect TV card nr %d!\n",
			       minor, card);
			return -EBADRQC;
		}
		for (card_type = 1;
		     card_type < sizeof(rcv_infos)/sizeof(struct rcv_info); 
		     card_type++) {
			if (rcv_infos[card_type].bttv_id == type &&
			    (rcv_infos[card_type].card_id == 0 ||
			     rcv_infos[card_type].card_id == cardid)) {
				gpio_mask = rcv_infos[card_type].gpio_mask;
				gpio_enable = rcv_infos[card_type].gpio_enable;
				gpio_lock_mask = rcv_infos[card_type].gpio_lock_mask;
				gpio_xor_mask = rcv_infos[card_type].gpio_xor_mask;
				soft_gap = rcv_infos[card_type].soft_gap;
				sample_rate = rcv_infos[card_type].sample_rate;
				code_length = rcv_infos[card_type].code_length;
				break;
			}
		}
		if (type==BTTV_AVPHONE98 && cardid==0x00011461)	{
			type = BTTV_AVERMEDIA98;
		}
		if (type==BTTV_AVERMEDIA98 && cardid==0x00041461) {
			type = BTTV_AVPHONE98;
		}
		if (card_type == sizeof(rcv_infos)/sizeof(struct rcv_info)) {
			printk(LOGHEAD "TV card type %x not supported!\n",
			       minor, type);
			return -EBADRQC;
		}
	}

	request_module("lirc_dev");

	return gpio_remote_init();
}

/*
 *
 */
void cleanup_module(void)
{
	int ret;

	ret = lirc_unregister_plugin(minor);
 
	if (0 > ret) {
		printk(LOGHEAD "error in lirc_unregister_minor: %d\n"
		       "Trying again...\n",
		       minor, ret);

		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(HZ);

		ret = lirc_unregister_plugin(minor);
 
		if (0 > ret) {
			printk(LOGHEAD "error in lirc_unregister_minor: %d!!!\n",
			       minor, ret);
			return;
		}
	}

	dprintk(LOGHEAD "module successfully unloaded\n", minor);
}
#endif

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-basic-offset: 8
 * End:
 */
