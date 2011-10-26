/*      $Id: lirc_i2c.c,v 1.11 2001/02/20 21:33:45 columbus Exp $      */

/*
 * i2c IR lirc plugin for Hauppauge and Pixelview cards - new 2.3.x i2c stack
 * (c) 2000 Gerd Knorr <kraxel@goldbach.in-berlin.de>
 * modified for PixelView (BT878P+W/FM) by
 *      Michal Kochanowicz <mkochano@pld.org.pl>
 *      Christoph Bartelmus <lirc@bartelmus.de>
 *
 * parts are cut&pasted from the old lirc_haup.c driver
 *
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < 0x020200
#error "--- Sorry, this driver needs kernel version 2.2.0 or higher. ---"
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/malloc.h>
#include <linux/i2c.h>

#ifndef I2C_CLIENT_END
#error "********************************************************"
#error " Sorry, this driver needs the new I2C stack.            "
#error " You can get it at http://www2.lm-sensors.nu/~lm78/.    "
#error "********************************************************"
#endif

#include <linux/i2c-algo-bit.h>

#include <asm/semaphore.h>

#include "../lirc_dev/lirc_dev.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#include "../drivers/char/bttv.h"
#else
#include "../drivers/media/video/bttv.h"
#endif

struct IR {
	struct lirc_plugin l;
	struct i2c_client  c;
	int nextkey;
	unsigned char b[3];
};

/* ----------------------------------------------------------------------- */
/* insmod parameters                                                       */

static int debug   = 0;    /* debug output */
static int minor   = -1;   /* minor number */

MODULE_PARM(debug,"i");
MODULE_PARM(minor,"i");

#define dprintk if (debug) printk

/* ----------------------------------------------------------------------- */

#define DEVICE_NAME "lirc_i2c"

/*
 * If this key changes, a new key was pressed.
 */
#define REPEAT_TOGGLE_0      192
#define REPEAT_TOGGLE_1      224

/* ----------------------------------------------------------------------- */

static inline int reverse(int data, int bits)
{
	int i;
	int c;
	
	for (c=0,i=0; i<bits; i++) {
		c |= (((data & (1<<i)) ? 1:0)) << (bits-1-i);
	}

	return c;
}

static int get_key_haup(void* data, unsigned char* key, int key_no)
{
	struct IR *ir = data;
        unsigned char buf[3];
	__u16 toggle_bit, code;

	if (ir->nextkey != -1) {
		/* pass second byte */
		*key = ir->nextkey;
		ir->nextkey = -1;
		return 0;
	}

	/* poll IR chip */
	if (3 == i2c_master_recv(&ir->c,buf,3)) {
		ir->b[0] = buf[0];
		ir->b[1] = buf[1];
		ir->b[2] = buf[2];
		dprintk(KERN_DEBUG DEVICE_NAME ": key (0x%02x/0x%02x)\n",
			ir->b[0], ir->b[1]);
	} else {
		dprintk(KERN_DEBUG DEVICE_NAME ": read error\n");
		/* keep last successfull read buffer */
	}

	/* key pressed ? */
	if (ir->b[0] != REPEAT_TOGGLE_0 && ir->b[0] != REPEAT_TOGGLE_1)
		return -1;
		
	/* look what we have */
	toggle_bit=(ir->b[0]&0x20) ? 0x800:0;
	code = (0x1000 | toggle_bit | (ir->b[1]>>2));

	/* return it */
	*key        = (code >> 8) & 0xff;
	ir->nextkey =  code       & 0xff;
	return 0;
}

static int get_key_pixelview(void* data, unsigned char* key, int key_no)
{
	struct IR *ir = data;
        unsigned char b;
	
	/* poll IR chip */
	if (1 != i2c_master_recv(&ir->c,&b,1)) {
		dprintk(KERN_DEBUG DEVICE_NAME ": read error\n");
		return -1;
	}
	dprintk(KERN_DEBUG DEVICE_NAME ": key %02x\n", b);
	*key = b;
	return 0;
}

static int get_key_pv951(void* data, unsigned char* key, int key_no)
{
	struct IR *ir = data;
        unsigned char b;
	static unsigned char codes[4];
	
	if(key_no>0)
	{
		if(key_no>=4) {
			dprintk(KERN_DEBUG DEVICE_NAME
				": something wrong in get_key_pv951\n");
			return -EBADRQC;
		}
		*key = codes[key_no];
		return 0;
	}
	
	/* poll IR chip */
	if (1 != i2c_master_recv(&ir->c,&b,1)) {
		dprintk(KERN_DEBUG DEVICE_NAME ": read error\n");
		return -1;
	}
	/* ignore 0xaa */
	if (b==0xaa)
		return -1;
	dprintk(KERN_DEBUG DEVICE_NAME ": key %02x\n", b);
	
	codes[2] = reverse(b,8);
	codes[3] = (~codes[2])&0xff;
	codes[0] = 0x61;
	codes[1] = 0xD6;
	
	*key=codes[0];
	return 0;
}

static void set_use_inc(void* data)
{
	struct IR *ir = data;

	/* lock bttv in memory while /dev/lirc is in use  */
	if (ir->c.adapter->inc_use) 
		ir->c.adapter->inc_use(ir->c.adapter);

	MOD_INC_USE_COUNT;
}

static void set_use_dec(void* data)
{
	struct IR *ir = data;

	if (ir->c.adapter->dec_use) 
		ir->c.adapter->dec_use(ir->c.adapter);
	MOD_DEC_USE_COUNT;
}

static struct lirc_plugin lirc_template = {
	name:        "lirc_i2c",
	set_use_inc: set_use_inc,
	set_use_dec: set_use_dec
};

/* ----------------------------------------------------------------------- */

static int ir_attach(struct i2c_adapter *adap, int addr,
		      unsigned short flags, int kind);
static int ir_detach(struct i2c_client *client);
static int ir_probe(struct i2c_adapter *adap);
static int ir_command(struct i2c_client *client, unsigned int cmd, void *arg);

static struct i2c_driver driver = {
        name:           "i2c ir driver",
        id:             I2C_DRIVERID_EXP3, /* FIXME */
        flags:          I2C_DF_NOTIFY,
        attach_adapter: ir_probe,
        detach_client:  ir_detach,
        command:        ir_command,
};

static struct i2c_client client_template = 
{
        name:   "unset",
        driver: &driver
};

static int ir_attach(struct i2c_adapter *adap, int addr,
		     unsigned short flags, int kind)
{
        struct IR *ir;
	
        client_template.adapter = adap;
        client_template.addr = addr;
	
        if (NULL == (ir = kmalloc(sizeof(struct IR),GFP_KERNEL)))
                return -ENOMEM;
        memcpy(&ir->l,&lirc_template,sizeof(struct lirc_plugin));
        memcpy(&ir->c,&client_template,sizeof(struct i2c_client));
	
	ir->c.adapter = adap;
	ir->c.addr    = addr;
	ir->c.data    = ir;
	ir->l.data    = ir;
	ir->l.minor   = minor;
	ir->l.sample_rate = 10;
	ir->nextkey   = -1;

	switch(addr)
	{
	case 0x64:
		strcpy(ir->c.name,"Pixelview IR");
		ir->l.code_length = 8;
		ir->l.get_key=get_key_pixelview;
		break;
	case 0x4b:
		strcpy(ir->c.name,"PV951 IR");
		ir->l.code_length = 32;
		ir->l.get_key=get_key_pv951;
		break;
	case 0x18:
	case 0x1a:
		strcpy(ir->c.name,"Hauppauge IR");
		ir->l.code_length = 13;
		ir->l.get_key=get_key_haup;
		break;
	default:
		/* shouldn't happen */
		printk("lirc_i2c: Huh? unknown i2c address (0x%02x)?\n",addr);
		kfree(ir);
		return -1;
	}
	printk("lirc_i2c: chip found @ 0x%02x (%s)\n",addr,ir->c.name);
	
	/* register device */
	i2c_attach_client(&ir->c);
	ir->l.minor = lirc_register_plugin(&ir->l);
	if (ir->c.adapter->inc_use)
		ir->c.adapter->inc_use(ir->c.adapter);
	
	return 0;
}

static int ir_detach(struct i2c_client *client)
{
        struct IR *ir = client->data;
	
	/* unregister device */
	if (ir->c.adapter->dec_use)
		ir->c.adapter->dec_use(ir->c.adapter);
	lirc_unregister_plugin(ir->l.minor);
	i2c_detach_client(&ir->c);

	/* free memory */
	kfree(ir);
	return 0;
}

static int ir_probe(struct i2c_adapter *adap) {
	
	/* The external IR receiver is at i2c address 0x34 (0x35 for
	   reads).  Future Hauppauge cards will have an internal
	   receiver at 0x30 (0x31 for reads).  In theory, both can be
	   fitted, and Hauppauge suggest an external overrides an
	   internal. 
	   
	   That's why we probe 0x1a (~0x34) first. CB 
	*/
	
	static const int probe[] = { 0x1a, 0x18, 0x4b, 0x64, -1};
	struct i2c_client c; char buf; int i,rc;

	if (adap->id == (I2C_ALGO_BIT | I2C_HW_B_BT848)) {
		memset(&c,0,sizeof(c));
		c.adapter = adap;
		for (i = 0; -1 != probe[i]; i++) {
			c.addr = probe[i];
			rc = i2c_master_recv(&c,&buf,1);
			dprintk("lirc_i2c: probe 0x%02x @ %s: %s\n",
				probe[i], adap->name, 
				(1 == rc) ? "yes" : "no");
			if (1 == rc)
				ir_attach(adap,probe[i],0,0);
		}
	}
	return 0;
}

static int ir_command(struct i2c_client *client,unsigned int cmd, void *arg)
{
	/* nothing */
	return 0;
}

/* ----------------------------------------------------------------------- */

#ifdef MODULE
int init_module(void)
#else
int lirc_i2c_init(void)
#endif
{
	request_module("bttv");
	i2c_add_driver(&driver);
	return 0;
}

#ifdef MODULE
void cleanup_module(void)
{
	i2c_del_driver(&driver);
}
#endif

/*
 * Overrides for Emacs so that we follow Linus's tabbing style.
 * ---------------------------------------------------------------------------
 * Local variables:
 * c-basic-offset: 8
 * End:
 */
