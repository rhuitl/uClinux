/*
 *  ==FILEVERSION 9906180==
 *
 * ppp_mppe.c - MPPE "compressor/decompressor" module.
 *
 * Copyright (c) 1994 Árpád Magosányi <mag@bunuel.tii.matav.hu>
 * All rights reserved.
 * Copyright (c) 1999 Tim Hockin, Cobalt Networks Inc. <thockin@cobaltnet.com>
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation is hereby granted, provided that the above copyright
 * notice appears in all copies.  This software is provided without any
 * warranty, express or implied. The Australian National University
 * makes no representations about the suitability of this software for
 * any purpose.
 *
 * IN NO EVENT SHALL THE AUSTRALIAN NATIONAL UNIVERSITY BE LIABLE TO ANY
 * PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF
 * THE AUSTRALIAN NATIONAL UNIVERSITY HAS BEEN ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * THE AUSTRALIAN NATIONAL UNIVERSITY SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE AUSTRALIAN NATIONAL UNIVERSITY HAS NO
 * OBLIGATION TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS,
 * OR MODIFICATIONS.
 *
 * From: deflate.c,v 1.1 1996/01/18 03:17:48 paulus Exp
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/malloc.h>

#undef VERSION
/* a nice define to generate linux version numbers */
#define VERSION(major,minor,patch) (((((major)<<8)+(minor))<<8)+(patch))

#if LINUX_VERSION_CODE >= VERSION(2,1,4)
#include <linux/vmalloc.h>
#endif
#include <linux/errno.h>
#include <linux/sched.h>	/* to get the struct task_struct */
#include <linux/string.h>	/* used in new tty drivers */
#include <linux/signal.h>	/* used in new tty drivers */

#include <asm/system.h>

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/ioctl.h>

#include <linux/ppp_defs.h>
#include <linux/ppp-comp.h>
#include "rc4.h"
#include "rc4_enc.c"
#include "sha1dgst.c"
#include "mppe.h"

/*
 * State for a mppe "(de)compressor".
 */
struct ppp_mppe_state {
    unsigned int	ccount; /*coherency count */
    RC4_KEY		RC4_send_key; /* chap-ms-v2 dictates 2 keys */
    RC4_KEY		RC4_recv_key;
    unsigned char	session_send_key[16];
    unsigned char	session_recv_key[16];
    unsigned char	master_send_key[16];
    unsigned char	master_recv_key[16];
    int			keylen;
    int                 stateless;
    int                 decomp_error;
    unsigned int	bits;
    int			unit;
    int			debug;
    int			mru;
    struct compstat 	stats;
};

#define MPPE_CCOUNT_FROM_PACKET(ibuf)	((((ibuf)[4] & 0x0f) << 8) + (ibuf)[5])
#define MPPE_BITS(ibuf) 	((ibuf)[4] & 0xf0 )
#define MPPE_CTRLHI(state)	((((state)->ccount & 0xf00)>>8)|((state)->bits))
#define MPPE_CTRLLO(state)	((state)->ccount & 0xff)
 
#define MPPE_OVHD		4

/* Procedures from the MPPE draft */
static void
mppe_synchronize_key(struct ppp_mppe_state *state)
{
    /* get new keys and flag our state as such */
    RC4_set_key(&(state->RC4_send_key),state->keylen,state->session_send_key);
    RC4_set_key(&(state->RC4_recv_key),state->keylen,state->session_recv_key);

    state->bits=MPPE_BIT_FLUSHED|MPPE_BIT_ENCRYPTED;
}


static void
mppe_initialize_key(struct ppp_mppe_state *state)
{
    /* generate new session keys */
    GetNewKeyFromSHA(state->master_send_key, state->master_send_key,
	state->keylen, state->session_send_key);
    GetNewKeyFromSHA(state->master_recv_key, state->master_recv_key,
	state->keylen, state->session_recv_key);

    if(state->keylen == 8) {
	/* cripple them from 64bit->40bit */
        state->session_send_key[0]=state->session_recv_key[0] = MPPE_40_SALT0;
        state->session_send_key[1]=state->session_recv_key[1] = MPPE_40_SALT1;
        state->session_send_key[2]=state->session_recv_key[2] = MPPE_40_SALT2;
    }

    mppe_synchronize_key(state);
}


static void
mppe_change_key(struct ppp_mppe_state *state)
{
    unsigned char InterimSendKey[16];
    unsigned char InterimRecvKey[16];

    /* get temp keys */
    GetNewKeyFromSHA(state->master_send_key, state->session_send_key,
	state->keylen, InterimSendKey);
    GetNewKeyFromSHA(state->master_recv_key, state->session_recv_key,
	state->keylen, InterimRecvKey);

    /* build RC4 keys from the temp keys */
    RC4_set_key(&(state->RC4_send_key), state->keylen, InterimSendKey);
    RC4_set_key(&(state->RC4_recv_key), state->keylen, InterimRecvKey);

    /* make new session keys */
    RC4(&(state->RC4_send_key), state->keylen, InterimSendKey,
	state->session_send_key);
    RC4(&(state->RC4_recv_key), state->keylen, InterimRecvKey,
	state->session_recv_key);

    if(state->keylen == 8)
    {
	/* cripple them from 64->40 bits*/
        state->session_send_key[0]=state->session_recv_key[0] = MPPE_40_SALT0;
        state->session_send_key[1]=state->session_recv_key[1] = MPPE_40_SALT1;
        state->session_send_key[2]=state->session_recv_key[2] = MPPE_40_SALT2;
    }

    /* make the final rc4 keys */
    RC4_set_key(&(state->RC4_send_key), state->keylen, state->session_send_key);
    RC4_set_key(&(state->RC4_recv_key), state->keylen, state->session_recv_key);

    state->bits=MPPE_BIT_ENCRYPTED;
}


#ifdef DEBUG
/* Utility procedures to print a buffer in hex/ascii */
static void
ppp_print_hex (register __u8 *out, const __u8 *in, int count)
{
	register __u8 next_ch;
	static char hex[] = "0123456789ABCDEF";

	while (count-- > 0) {
		next_ch = *in++;
		*out++ = hex[(next_ch >> 4) & 0x0F];
		*out++ = hex[next_ch & 0x0F];
		++out;
	}
}


static void
ppp_print_char (register __u8 *out, const __u8 *in, int count)
{
	register __u8 next_ch;

	while (count-- > 0) {
		next_ch = *in++;

		if (next_ch < 0x20 || next_ch > 0x7e)
			*out++ = '.';
		else {
			*out++ = next_ch;
			if (next_ch == '%')   /* printk/syslogd has a bug !! */
				*out++ = '%';
		}
	}
	*out = '\0';
}


static void
ppp_print_buffer (const __u8 *name, const __u8 *buf, int count)
{
	__u8 line[44];

	if (name != (__u8 *) NULL)
		printk (KERN_DEBUG "ppp: %s, count = %d\n", name, count);

	while (count > 8) {
		memset (line, 32, 44);
		ppp_print_hex (line, buf, 8);
		ppp_print_char (&line[8 * 3], buf, 8);
		printk (KERN_DEBUG "%s\n", line);
		count -= 8;
		buf += 8;
	}

	if (count > 0) {
		memset (line, 32, 44);
		ppp_print_hex (line, buf, count);
		ppp_print_char (&line[8 * 3], buf, count);
		printk (KERN_DEBUG "%s\n", line);
	}
}
#endif

/* our 'compressor' proper */
static void	*mppe_comp_alloc __P((unsigned char *, int));
static void	mppe_comp_free __P((void *));
static int	mppe_comp_init __P((void *, unsigned char *,
					int, int, int, int));
static int	mppe_decomp_init __P((void *, unsigned char *,
					int, int, int, int, int));
static int	mppe_compress __P((void *, unsigned char *,
					unsigned char *, int, int));
static void	mppe_incomp __P((void *, unsigned char *, int));
static int	mppe_decompress __P((void *, unsigned char *,
					int, unsigned char *, int));
static void	mppe_comp_reset __P((void *));
static void	mppe_comp_stats __P((void *, struct compstat *));


/* cleanup the compressor */
static void
mppe_comp_free(void *arg)
{
    struct ppp_mppe_state *state = (struct ppp_mppe_state *) arg;

    if (state) {
	    kfree(state);
	    MOD_DEC_USE_COUNT;
    }
}


/* allocate space for a compressor.  */
static void *
mppe_comp_alloc(unsigned char *options, int opt_len)
{
    struct ppp_mppe_state *state;

    if (((2*8)+3 != opt_len && (2*16)+3 != opt_len) /* 2 keys + 3 */ 
       || options[0] != CI_MPPE || options[1] != CILEN_MPPE) {
	    printk(KERN_DEBUG "compress rejected: opt_len=%u,o[0]=%x,o[1]=%x\n",
		opt_len,options[0],options[1]);
	    return NULL;
    }

    state = (struct ppp_mppe_state *)kmalloc(sizeof(*state), GFP_KERNEL);
    if (state == NULL)
	return NULL;

    MOD_INC_USE_COUNT;

    memset (state, 0, sizeof (struct ppp_mppe_state));

    /* write the data in options to the right places */
    memcpy(&state->stateless,options+2,1);

    state->keylen = (opt_len-3)/2;
    memcpy(state->master_send_key,options+3,state->keylen);
    memcpy(state->master_recv_key,options+3+state->keylen,state->keylen);

    mppe_initialize_key(state);

    return (void *) state;
}


static int
mppe_comp_init(void *arg, unsigned char *options, int opt_len, int unit, 
		int hdrlen, int debug)
{
    struct ppp_mppe_state *state = (struct ppp_mppe_state *)arg;

    if (options[0] != CI_MPPE || options[1] != CILEN_MPPE) {
    	printk(KERN_DEBUG "compress rejected: opt_len=%u,o[0]=%x,o[1]=%x\n",
	    opt_len,options[0],options[1]);
	return 0;
    }

    state->ccount = 0;
    state->unit  = unit;
    state->debug = debug;

    /* 19 is the min (2*keylen) + 3 */
    if(opt_len >= 19) {
        memcpy(&state->stateless,options+2,1);

    	state->keylen = (opt_len-3)/2;
    	memcpy(state->master_send_key,options+3,state->keylen);
    	memcpy(state->master_recv_key,options+3+state->keylen,state->keylen);

    	mppe_initialize_key(state);
    }

    return 1;
}


static int
mppe_decomp_init(void *arg, unsigned char *options, int opt_len, int unit,
		int hdrlen, int mru, int debug)
{
    struct ppp_mppe_state *state = (struct ppp_mppe_state *)arg;

    if (options[0] != CI_MPPE || options[1] != CILEN_MPPE) {
	printk(KERN_DEBUG"options are bad: %x %x\n",options[0],options[1]);
	return 0;
    }

    state->ccount = 0;
    state->unit  = unit;
    state->debug = debug;
    state->mru = mru;

    /* 19 is the min (2*keylen)+3 */
    if(opt_len >= 19) {
	memcpy(&state->stateless,options+2,1);

	state->keylen = (opt_len-3)/2;
	memcpy(state->master_send_key,options+3,state->keylen);
	memcpy(state->master_recv_key,options+3+state->keylen,state->keylen);

	mppe_initialize_key(state);
    }

    return 1;
}


static void
mppe_comp_reset(void *arg)
{
    struct ppp_mppe_state *state = (struct ppp_mppe_state *)arg;

    printk(KERN_DEBUG "mppe_comp_reset\n");

    (state->stats).in_count = 0;
    (state->stats).bytes_out = 0;
    (state->stats).ratio = 0;

    mppe_synchronize_key(state);
}


static void
mppe_update_count(struct ppp_mppe_state *state)
{
    if(!state->stateless)
    {
        if ( 0xff == (state->ccount&0xff)){ 
	    /* time to change keys */
	    if ( 0xfff == (state->ccount&0xfff)){
		state->ccount = 0;
	    } else {
		(state->ccount)++;
	    }
	    mppe_change_key(state);
        } else {
            state->ccount++;
        }
    } else {
        if ( 0xFFF == (state->ccount & 0xFFF)) {
	    state->ccount = 0;
        } else {
	    (state->ccount)++;
	}
       	mppe_change_key(state);
    }
}


/* the big nasty */
int
mppe_compress(void *arg, unsigned char *rptr, unsigned char *obuf, 
		int isize, int osize)
{
    struct ppp_mppe_state *state = (struct ppp_mppe_state *) arg;
    int proto, olen;
    unsigned char *wptr;

#ifdef DEBUG
    ppp_print_buffer("mppe_encrypt",rptr,isize);
#endif

    if(osize < isize+MPPE_OVHD) {
	printk(KERN_DEBUG "Not enough space to encrypt packet: %d<%d+%d!\n",
		isize, osize, MPPE_OVHD);
	return 0;
    }

    /* Check that the protocol is in the range we handle. */
    proto = PPP_PROTOCOL(rptr);
    if (proto < 0x0021 || proto > 0x00FA )
	return 0;

    wptr = obuf;

    /* Copy over the PPP header and store the 2-byte sequence number. */
    wptr[0] = PPP_ADDRESS(rptr);
    wptr[1] = PPP_CONTROL(rptr);
    wptr[2] = PPP_MPPE >>8;
    wptr[3] = PPP_MPPE;
    wptr += PPP_HDRLEN;
    wptr[0] = MPPE_CTRLHI(state);
    wptr[1] = MPPE_CTRLLO(state);
    wptr += 2;

    state->bits=MPPE_BIT_ENCRYPTED;
    mppe_update_count(state);

    /* read from rptr, write to wptr adjust for PPP_HDRLEN */
    RC4(&(state->RC4_send_key),isize-2,rptr+2,wptr);
    olen=isize+MPPE_OVHD;

    (state->stats).comp_bytes += isize;
    (state->stats).comp_packets++;

#ifdef DEBUG
    ppp_print_buffer("mppe_encrypt out",obuf,olen);
#endif

    return olen;
}


static void
mppe_comp_stats(void *arg, struct compstat *stats)
{
    struct ppp_mppe_state *state = (struct ppp_mppe_state *)arg;

    /* since we don't REALLY compress at all, this should be OK */
    (state->stats).in_count = (state->stats).unc_bytes;
    (state->stats).bytes_out = (state->stats).comp_bytes;

    /* this _SHOULD_ always be 1 */
    (state->stats).ratio = (state->stats).in_count/(state->stats).bytes_out;

    *stats = state->stats;
   
}


/* the other big nasty */
int
mppe_decompress(void *arg, unsigned char *ibuf, int isize, 
		unsigned char *obuf, int osize)
{
    struct ppp_mppe_state *state = (struct ppp_mppe_state *)arg;
    int seq;

    if (isize <= PPP_HDRLEN + MPPE_OVHD) {
	if (state->debug) {
	    printk(KERN_DEBUG "mppe_decompress%d: short packet (len=%d)\n",
		state->unit, isize);
	}

	return DECOMP_ERROR;
    }

    /* Check the sequence number. */
    seq = MPPE_CCOUNT_FROM_PACKET(ibuf);

    if(!state->stateless && (MPPE_BITS(ibuf) & MPPE_BIT_FLUSHED)) {
        state->decomp_error = 0;
        state->ccount = seq;
    }

    if(state->decomp_error) {
        return DECOMP_ERROR;
    }

    if (seq != state->ccount) {
	if (state->debug) {
	    printk(KERN_DEBUG "mppe_decompress%d: bad seq # %d, expected %d\n",
		   state->unit, seq, state->ccount);
	}

        while(state->ccount != seq) {
            mppe_update_count(state);
	}

        mppe_update_count(state);

	return DECOMP_ERROR;
    }

    /*
     * Fill in the first part of the PPP header.  The protocol field
     * comes from the decompressed data.
     */
    obuf[0] = PPP_ADDRESS(ibuf);
    obuf[1] = PPP_CONTROL(ibuf);
    obuf += 2;

    if(!(MPPE_BITS(ibuf) & MPPE_BIT_ENCRYPTED)) {
        printk(KERN_DEBUG"ERROR: not an encrypted packet");
        mppe_synchronize_key(state);
	return DECOMP_ERROR;
    } else {
	if(!state->stateless && (MPPE_BITS(ibuf) & MPPE_BIT_FLUSHED))
	    mppe_synchronize_key(state);
	mppe_update_count(state);

	/* decrypt - adjust for PPP_HDRLEN + MPPE_OVHD - mru should be OK */
	RC4(&(state->RC4_recv_key),isize-6,ibuf+6,obuf);

	(state->stats).unc_bytes += (isize-MPPE_OVHD);
	(state->stats).unc_packets ++;

	return isize-MPPE_OVHD;
    }
}


/* Incompressible data has arrived - add it to the history.  */
static void
mppe_incomp(void *arg, unsigned char *ibuf, int icnt)
{
    struct ppp_mppe_state *state = (struct ppp_mppe_state *)arg;

    (state->stats).inc_bytes += icnt;
    (state->stats).inc_packets++;
}


/*************************************************************
 * Module interface table
 *************************************************************/

/* These are in ppp.c */
extern int  ppp_register_compressor   (struct compressor *cp);
extern void ppp_unregister_compressor (struct compressor *cp);

/*
 * Procedures exported to if_ppp.c.
 */
struct compressor ppp_mppe = {
    CI_MPPE,			/* compress_proto */
    mppe_comp_alloc,		/* comp_alloc */
    mppe_comp_free,		/* comp_free */
    mppe_comp_init,		/* comp_init */
    mppe_comp_reset,		/* comp_reset */
    mppe_compress,		/* compress */
    mppe_comp_stats,		/* comp_stat */
    mppe_comp_alloc,		/* decomp_alloc */
    mppe_comp_free,		/* decomp_free */
    mppe_decomp_init,		/* decomp_init */
    mppe_comp_reset,		/* decomp_reset */
    mppe_decompress,		/* decompress */
    mppe_incomp,		/* incomp */
    mppe_comp_stats,		/* decomp_stat */
};


#ifdef MODULE
/*************************************************************
 * Module support routines
 *************************************************************/

int
init_module(void)
{  
    int answer = ppp_register_compressor(&ppp_mppe);
    if (answer == 0) {
    	printk(KERN_INFO "PPP MPPE compression module registered\n");
    }
    return answer;
}
     

void
cleanup_module(void)
{
    if (MOD_IN_USE) {
    	printk (KERN_INFO "MPPE module busy, remove delayed\n");
    } else {
	ppp_unregister_compressor (&ppp_mppe);
	printk(KERN_INFO "PPP MPPE compression module unregistered\n");
    }
}
#endif /* MODULE */
