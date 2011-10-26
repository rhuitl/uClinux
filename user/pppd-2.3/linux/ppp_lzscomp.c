/* -*- mode: c; c-basic-offset: 1 -*-

 * $Id: ppp_lzscomp.c,v 1.1.1.1 1999-11-22 03:47:54 christ Exp $
 *
 * PPP link compression code for Stac LZS support
 * Initially just a RFC1974 decompressor is provided
 * If interest is sufficient a compressor may follow
 *
 * GPL - you know
 *
 * Compile with:
 *  gcc -O2 -I/usr/src/linux/include -D__KERNEL__ -DMODULE -c isdn_lzscomp.c
 */

/*
 *  ==FILEVERSION 9807110==
 *
 *  NOTE TO MAINTAINERS:
 *     If you modify this file at all, please set the above date.
 *     ppp_defs.h is shipped with a PPP distribution as well as with the kernel;
 *     if everyone increases the FILEVERSION number above, then scripts
 *     can do the right thing when deciding whether to install a new ppp_defs.h
 *     file.  Don't change the format of that line otherwise, so the
 *     installation script can recognize it.
 */

#ifndef MODULE
#error This file must be compiled as a module.
#endif

static const char
  rcsid[] = "$Id: ppp_lzscomp.c,v 1.1.1.1 1999-11-22 03:47:54 christ Exp $";

/* Wow. No wonder this needs so long to compile. This include list
 * is a shameless rip from other compressor code. Hopefully no (C)
 * violation ;)
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/config.h>

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fcntl.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/in.h>
#include <linux/malloc.h>
#include <linux/tty.h>
#include <linux/errno.h>
#include <linux/sched.h>	/* to get the struct task_struct */
#include <linux/string.h>	/* used in new tty drivers */
#include <linux/signal.h>	/* used in new tty drivers */

#include <asm/system.h>
#include <asm/bitops.h>
#include <asm/segment.h>
#include <asm/byteorder.h>
#include <asm/types.h>

#include <linux/if.h>


#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/ioctl.h>

#include <linux/ppp_defs.h>

/* #include <linux/netprotocol.h> */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <linux/ppp-comp.h>

#include "ppp_lzscomp.h"

/*
   #define TEST_BROKEN_SEQNO 10
   #define TEST_BROKEN_CCNT 10
 */

#define TEST_COMP_BROKEN_CCNT 10
#define TEST_COMP_BROKEN_SEQNO 10

/*
 * Values for debug:
 * 0 - no additional debug info
 * 1 - normal debug info
 * 2 - redundant debug info
 * 3 - heavy debug (packet dumps etc)
 */

static int debug = 0;

/*
 * Values for comp:
 * 0 - do no compression at all, send uncompressed
 * 1 - do absolute minimal compression (somewhat fast)
 * ...
 * 8 - do optimal compression (heavy but still useable)
 * 9 - do ultimate compression (chews up nonsense amounts of CPU time)
 */

static int comp = 0;

/*
 * Tweak flags. If none of these is set, the code will try to accept any
 * input that follows the RFCs and produce output as close to the RFC as
 * possible. Setting some of the flags may lead to behavior that is indeed
 * a RFC violation. Bad enough, some are necessary to talk to certain
 * peers.
 *
 * The first tweak bits are for talking to an Ascend Max 4000 E1 running
 * TAOS 5.0Ap13 (my only test peer). I've noticed _severe_ amounts of
 * transmission errors talking to 6.0.x, making compression nearly use-
 * less due to permanent resets. May be a prob with our M4k, though.
 *
 */

/* The history number in mode 3 (seqno) reset requests MUST be specified
   explicitely, even if 1 */
#define LZS_TW_M3_RSRQ_EXP_HIST	0x00000001

/* The history number in mode 3 (seqno) reset acks MUST NOT be reflected
   from the request, but left out */
#define LZS_TW_M3_RSAK_NO_HIST	0x00000002

/* The history number in mode 4 (ext) reset requests MUST be specified
   explicitely, despite the fact that it cannot be anything but 1 */
#define LZS_TW_M4_RSRQ_NO_HIST	0x00000004

/* My Ascend will not recongnize mode 3 reset requests if no history is
   tacked on. On the other hand, it does send the reset acks that stem
   from those requests _without_ the history tacked on. It will also
   not recognize any reset ack _with_ a history tacked on in that mode.
   To fat it up, in mode 4 it recognizes reset requests only if _no_
   hist is tacked on. I have a Ticket number open for that with Ascend
   EMEA support, but dunno whether they want to fix this... */

#define LZS_TWEAK_ASCEND	0x00000007

static int tweak = LZS_TWEAK_ASCEND;

#undef VERSION
/* a nice define to generate linux version numbers */
#define VERSION(major,minor,patch) (((((major)<<8)+(minor))<<8)+(patch))

#if LINUX_VERSION_CODE > VERSION(2,1,0)
MODULE_AUTHOR("Andre Beck <beck@ibh.de>");
MODULE_DESCRIPTION("LZS Compression for async PPP");
MODULE_PARM(debug, "i");
MODULE_PARM(comp, "i");
MODULE_PARM(tweak, "i");
#endif

/*
 * I _have_ read Documentation/CodingStyle. I ignored the section about
 * 8 space indentations. Errare humanum est.
 *
 * Ok, get to the iron. We start with some structures to define a LZS
 * compressors state. Oops, read _de_compressor.
 */

/* LZS histories are 2048 Byte chunks of memory. We start with non-smart
   (read slow) indexing - running pointers follow when the code is working
   and someone actually notices its slow */

#define LZS_HISTORY_SIZE	2048
#define LZS_HISTORY_MASK	0x7ff	/* 2047 */
#define LZS_HASHTAB_SIZE	256

/* The number of bytes to compare before we consider to call memcmp(3)
   Empirical results:
   Linux/x86 on P54C: Appears that GNU C can optimize memcmp calls into
   direct inline assembly instructions so nearly no call overhead is
   there at all. The temporary manager doesn't seem to discover that
   the results of later additions actually drop out of the repz cmpsb,
   but hell - getting the rep is good enough. Thus we call memcmp on
   this architecture unconditionally to save time.

   Sun Ultra/gcc: memcmp has advantages, but only on long strings (this
   is RISC after all). 32 seems to be a good value.

   Alpha/cc: There were no advantages of memcmp in measurement. However,
   gccs milage may vary.

   Other: Not yet known.

   Semantics: Set to 0 to unconditionally use memcmp(3). Set to >0 to
   use memcmp(3) only when the string is at least that long.
   Undefine to completely wipe out memcmp(3) utilization.
 */

#if defined(__GNUC__)
#if defined(__i386__)
/* With GCC on i386, memcmp is intrinsic and will always be used */
#define LZS_MEMCMP_THRESHOLD 0
#endif /* defined(__i386__) */
#endif /* defined(__GNUC__) */

/* Some words about the implementation of the compressor:
   I started with brute force. This was - as expected - too slow for
   any realworld use, the only chance to get it somewhat useful was
   to limit search in a restrictive way. I then posted a question on
   how to implement LZS efficient in ISO C in comp.compression. As
   there were no immediate answers, I digged a bit on my own and found
   out that gzip/zlib (aka "deflate") uses a hash table in its LZ77
   stage. They generate hash chains from every 3-byte-match in the
   input and later traverse these hash chains. Inspired by this idea
   (which even is claimed to be patent free) I adapted the 3-byte-match
   to a 2-byte-match scheme. The hash chains do not grow without bounds
   as in deflate, instead I realized that I could store hash entries
   in a fixed mapping to the history. This even had the net effect of
   controlling LRU disposal of hash entries that are not relevant any
   longer because this hash entry map was a ring buffer the same way the
   history is one. This implementation performed much better than the
   brute force one, but I still was not pleased. The code that deals
   with the LRU aspects of the hash entries was complicated, hard to
   read and did cost some performance.
   I then got EMail response to my posting in comp.compression from
   David Carr - he gave me a bunch of valueable hints during our
   EMail conversation. The current implementation is still based on
   the hash idea like outlined above, but modified with these hints
   and tricks in mind:

   The barrier hash
   Instead of storing the actual value-range of indexes in the hash
   table and hash entries and actively clean them up in the LRU case
   as well as dealing with a NIL type index which must be faked some-
   how because 0 is a valid index, use much larger values. In the
   simplest case (as used here), just take unsigned longs. Of course
   these values must be masked whenever used as an index into a table,
   but this is necessary in surprisingly seldom cases. Most arithme-
   tics can be done as easy as before. The greatest effect of the
   barrier hash, however, is auto-scoping: Indexes that are no longer
   valid can easily be determined because they leave the LZ77 window.
   Thus both the hash table and hash entry list are invalidating them-
   selves automatically and don't need active cleaning except when the
   index wraps (which is quite seldom with unsigned long). Another big
   advantage of the barrier hash is that it makes compressor state re-
   sets very cheap. Just close the LZ77 window and move it far enough
   forward and the hash table and entries are invalidated automatically.
   My former implementation needed to clean out some 10K of memory in-
   stead. As resets may occur on every small packet, this is a hell of
   a lot more efficient. Due to the simplifications of the barrier
   hash, the hash entries are no longer complicated compounds but just
   a ring buffer of unsigned long "next" indexes.

   The sigma buffer
   As inspired from the good old "freeze" compressor, the sigma buffer
   is the idea to mirror the history. If you have a mirror history
   directly behind the real one, you can run string compares and other
   inner loop operations without taking care about the ring buffer
   wrapping: the operations just run into the mirror history. While
   freeze uses a relatively short max string length and thus did not
   mirror the complete history but just a tail (thus the name sigma
   buffer, a ring with a tail), LZS can code 2047 byte strings and
   I mirror the complete history (we could call it an 8-Buffer).

   Memcmp
   Another great hint from freeze was how to use memcmp(3) for the
   string matching. If you know that you need a string match longer
   than n and don't care about the length of the actual match if it
   is less than n+1, you can first memcmp(histidx, inputidx, n+1) and
   only if it succeeds count the remaining matching bytes. If the
   memcmp doesn't succeed, the match was shorter than n+1 and thus
   of no further interest.

 */

/* Chris Toreks hash function as also utilized in DB. Surprisingly
   simple but still performs great. An option for further optimization
   of the compressor would be to find a hash that hashes better, is
   faster and is applied incremental. */


#define HASHME(val, hash) ((hash<<5) + hash + val)

typedef struct _lzs_hist
{
  u8 *hist;			/* LZS_HISTORY_SIZE*2 allocation (8-Buffer) */
  u32 *hashtab;			/* LZS_HASHTAB_SIZE allocation */
  u32 *next;			/* LZS_HISTORY_SIZE allocation hash entries */
  u32 head;			/* current head index into history */
  int hlen;			/* bytes valid in history so far (comp) */
  u8 seqno;			/* next expected seqno of this history */
  u8 expra;			/* a reset request is outstanding */
  u8 rsid;			/* reset id used for this history */
}
LZSHist;

typedef struct _lzs_hists
{
  LZSHist *hists;
  u16 nhists;
}
LZSHists;

#define LZS_HMODE_TRASH		0	/* Trash hist after every frame */
#define LZS_HMODE_ONE		1	/* Exactly one hist */
#define LZS_HMODE_MANY		2	/* Multiple hists */

typedef struct _lzs_state
{
  LZSHists *h;			/* The allocated histories if any */
  u32 word;			/* bit blender */
  int left;			/* bits left in blender */
  u8 *inbuf;			/* where we read from (skbuff stuff is too */
  int inlen;			/* heavy to be used in every inline) */
  u8 hmode;			/* history mode (placed here for align) */
  u8 cmode;			/* check mode (dito) */
  u8 zstuff;			/* state of zero stuffing */
  u8 unit;			/* CCP unit */
  u16 ccnt;			/* Coherency Counter - Ext has only 1 hist */
  u8 rsid;			/* Next reset id to be used */
  u8 comp:1;			/* Flag: is this a compressor ? */
  u8 lastinc:1;			/* Flag: was the last frame incompressible ? */
  u8 ackrs:1;			/* Flag: ack a reset request inband (EXT) */
  struct compstat stats;	/* statistics sink */
  /* more to come */
}
LZSState;

static short compparms[10][2] =
{
 /* depth, maxlen */
  {0, 0},			/* 0 Actually a special case, these parms are not used */
  {0, 32},			/* 1 Consider only first match and max string len 32 */
  {1, 32},			/* 2 Consider two matches */
  {2, 64},			/* 3 You got the picture */
  {8, 256},			/* 4 */
  {16, 1024},			/* 5 */
  {32, 2047},			/* 6 */
  {64, 2047},			/* 7 */
  {128, 2047},			/* 8 */
  {2047, 2047}			/* 9 Full depth and max length - nonsense slow */
};

/* Alloc a bunch of hists or if this fails cleanup and return NULL */
static LZSHists *allocHists(u16 count, int comp)
{
  LZSHists *hs;
  LZSHist *hv;
  int i = 0;
  int gotall;

  hs = (LZSHists *) kmalloc(sizeof(LZSHists), GFP_KERNEL);
  if (!hs)
    return NULL;

  /* Could be more than a page */
  hv = (LZSHist *) vmalloc(sizeof(LZSHist) * count);
  if (!hv)
  {
    kfree(hs);
    return NULL;
  }
  memset(hv, 0, sizeof(LZSHist) * count);
  while (i < count)
  {
    /* 4096 is larger than a page on some systems */
    gotall = 1;
    hv[i].hist = (u8 *) vmalloc(LZS_HISTORY_SIZE * 2);
    if (!hv[i].hist)
      gotall = 0;
    if (comp)
    {
      /* Additional data structures for the compressor */
      if (hv[i].hist)
      {
	hv[i].next = (u32 *) vmalloc(sizeof(u32) * LZS_HISTORY_SIZE);
	if (hv[i].next)
	{
	  hv[i].hashtab = (u32 *) vmalloc(sizeof(u32) * LZS_HASHTAB_SIZE);
	  if (!hv[i].hashtab)
	    gotall = 0;
	}
	else
	  gotall = 0;
      }
    }
    if (!gotall)
    {
      /* Oops - have to clean the whole mess up ... */
      while (i-- >= 0)
      {
	if (hv[i].hist)
	  vfree(hv[i].hist);
	if (hv[i].next)
	  vfree(hv[i].next);
	if (hv[i].hashtab)
	  vfree(hv[i].hashtab);
      }
      vfree(hv);
      kfree(hs);
      return NULL;
    }
    /* The first expected seqno of a history is 1 */
    hv[i].seqno = 1;
    if (comp)
    {
      /* Initialize next buffer and hash table to 0 (hist doesn't need this) */
      memset(hv[i].next, 0, sizeof(u32) * LZS_HISTORY_SIZE);
      memset(hv[i].hashtab, 0, sizeof(32) * LZS_HASHTAB_SIZE);
      /* Initialize history head to 2048 (so 0 is out of scope) */
      hv[i].head = LZS_HISTORY_SIZE;
    }
    i++;
  }
  /* We got through getting all the mem - link it and return */
  hs->hists = hv;
  hs->nhists = count;
  return hs;
}

static void freeHists(LZSHists * hs)
{
  int i;
  for (i = 0; i < hs->nhists; i++)
  {
    if (hs->hists[i].hashtab)
      vfree(hs->hists[i].hashtab);
    if (hs->hists[i].next)
      vfree(hs->hists[i].next);
    vfree(hs->hists[i].hist);
  }
  vfree(hs->hists);
  kfree(hs);
}

static void lzsStats(void *state, struct compstat *stats)
{
  LZSState *s = (LZSState *) state;

  memcpy(stats, &s->stats, sizeof(struct compstat));
}

static void resetCompHist(LZSState * s, LZSHist * h)
{
  /* Reset the compressor state */
  u32 oldhead = h->head;

  h->hlen = 0;

  /* Use the barrier hash to invalidate the whole history in a hatch. It just
     moves all current indices beyond the barrier. Without this nice trick
     we would have to zero out approx. 10K memory - thanks David ;) */
  h->head += LZS_HISTORY_SIZE;

  if (h->head < oldhead)
  {
    /* We wrapped around index space. Make sure all hash table entries are
       invalidated - it is unlikely that they survived a full iteration
       about 2^32, but not impossible. For instance, it requires just
       two million uncompressible packets which cause a call to this
       function to wrap the space - certainly possible. */
    h->head = LZS_HISTORY_SIZE;
    memset(h->hashtab, 0, sizeof(u32) * LZS_HASHTAB_SIZE);
  }
}

static void lzsReset(void *state, unsigned char *packet)
{
  LZSState *s = (LZSState *) state;
  u16 hi;
  int code = CCP_CODE(packet);
  int id = CCP_ID(packet);
  int len = CCP_LENGTH(packet);
  unsigned char *data = &packet[CCP_HDRLEN];

  if (debug)
    printk(KERN_DEBUG "lzsReset: code %02x id %02x with %d data bytes\n",
	   code, id, len);

  if (s->comp)
  {
    switch (s->cmode)
    {
    case LZS_CMODE_EXT:
    case LZS_CMODE_SEQNO:
      if (len > 1)
      {
	hi = (data[0] << 8) | data[1];
      }
      else
      {
	hi = 1;
      }
      switch (s->hmode)
      {
      case LZS_HMODE_TRASH:
      case LZS_HMODE_ONE:
	if (hi != 1)
	{
	  printk(KERN_INFO "lzsReset: reset for hist %d in single hist mode\n", hi);
	  hi = 1;
	}
	break;
      case LZS_HMODE_MANY:
	if (hi > s->h->nhists)
	{
	  printk(KERN_INFO "lzsReset: reset for hist %d but only %d hists\n", hi,
		 s->h->nhists);
	  return;
	}
      }
      /* Ok, we reset the correct history */
      resetCompHist(s, &s->h->hists[hi - 1]);
      switch (s->cmode)
      {
      case LZS_CMODE_EXT:
	/* Remember that we did reset and prepare for sending an inband ack */
	s->ackrs = 1;
#if 0
	/* Tell the framework to NOT send a Reset Ack */
	rsparm->valid = 1;
	rsparm->rsend = 0;
#endif
	break;
      case LZS_CMODE_SEQNO:
#if 0
	/* Tell the framework to send a Reset Ack reflecting the Req */
	rsparm->valid = 1;
	rsparm->rsend = 1;
	rsparm->idval = 1;
	rsparm->id = id;
	if (!(tweak & LZS_TW_M3_RSAK_NO_HIST))
	{
	  if (rsparm->maxdlen >= len)
	  {
	    if (len == 2)
	    {
	      rsparm->dlen = len;
	      rsparm->dtval = 1;
	      rsparm->data[0] = data[0];
	      rsparm->data[1] = data[1];
	    }
	    else
	    {
	      printk(KERN_WARNING "lzsReset: unknown Reset Req Data - ignored\n");
	    }
	  }
	}
#endif
	break;
      }
      break;
    case LZS_CMODE_CRC:
    case LZS_CMODE_LCB:
    case LZS_CMODE_NONE:
    default:
      printk(KERN_INFO "lzsReset: cmode %d NYI - reset ignored\n", s->cmode);
    }
  }
  else
  {
    switch (s->cmode)
    {
    case LZS_CMODE_EXT:
      /* RFC 1962 states that an implementation which receives a Reset-Request
         MUST answer with a Reset-Ack. Thus the whole extended checkmode is
         a single RFC violation. But it's M$, so what... */
      s->rsid++;		/* Just to be sure */
      printk(KERN_INFO "lzsReset: reset ack rcvd in ext cmode - ignored\n");
      break;
    case LZS_CMODE_SEQNO:
      if (len > 1)
      {
	hi = (data[0] << 8) | data[1];
      }
      else
      {
	hi = 1;
      }
      switch (s->hmode)
      {
      case LZS_HMODE_TRASH:
      case LZS_HMODE_ONE:
	if (hi != 1)
	{
	  printk(KERN_INFO "lzsReset: reset for hist %d in single hist mode\n", hi);
	  hi = 1;
	}
	break;
      case LZS_HMODE_MANY:
	if (hi > s->h->nhists)
	{
	  printk(KERN_INFO "lzsReset: reset for hist %d but only %d hists\n", hi,
		 s->h->nhists);
	  return;
	}
      }
      /* Ok, we reset the correct history */
      if (s->h->hists[hi - 1].rsid != id)
	printk(KERN_INFO "lzsReset: reset id %d expected %d\n", id,
	       s->h->hists[hi - 1].rsid);
      s->h->hists[hi - 1].expra = 0;
      /* The next id must be incremented because we received an ack */
      s->rsid++;
      break;
    case LZS_CMODE_CRC:
    case LZS_CMODE_LCB:
    case LZS_CMODE_NONE:
    default:
      printk(KERN_INFO "lzsReset: cmode %d NYI - reset ignored\n", s->cmode);
    }
  }
}

/* Alloc space for a decompressor - number of histories is known here */

static void *lzsDecompAlloc(void *state, unsigned char *options, int opt_len,
			    int unit, int opthdr, int debug)
{
  u8 cmode;
  u16 nhists;
  LZSState *s;

  if (options[0] != CI_LZS_COMPRESS || options[1] != 3)
    return NULL;

  /* We need 2 configuration options: The number of histories and the
     check mode to use. The number is a short - we pass it in big endian */

  nhists = (options[2] << 8) | options[3];
  cmode = options[4];

  if (debug)
    printk(KERN_DEBUG "lzsDecompAlloc: hists %d cmode %d\n", nhists, cmode);

  if (cmode > LZS_CMODE_EXT || cmode == LZS_CMODE_CRC || cmode == LZS_CMODE_LCB)
  {
    printk(KERN_WARNING "lzsDecompAlloc: cmode %d not supported (yet)\n", cmode);
    return NULL;
  }

  /* Allocate the state */

  s = (LZSState *) kmalloc(sizeof(LZSState), GFP_KERNEL);
  if (!s)
    return NULL;

  MOD_INC_USE_COUNT;

  memset(s, 0, sizeof(LZSState));

  if (debug)
    printk(KERN_DEBUG "lzsDecompAlloc: Allocating decompressor\n");
  s->comp = 0;
  s->hmode = LZS_HMODE_ONE;
  switch (nhists)
  {
  case 0:
    s->hmode = LZS_HMODE_TRASH;
    /* We still need a hist here _during_ the packet decompression */
    /* This branch intentionally falls through */
  case 1:
    s->h = allocHists(1, s->comp);
    if (!s->h)
    {
      printk(KERN_WARNING "lzsAlloc: decomp history - out of mem\n");
      goto out_free;
    }
    break;
  default:
    s->hmode = LZS_HMODE_MANY;
    s->h = allocHists(nhists, s->comp);
    if (!s->h)
    {
      printk(KERN_WARNING "lzsAlloc: decomp %d histories - out of mem\n", nhists);
      goto out_free;
    }
    break;
  }
  if (debug)
    printk(KERN_DEBUG "lzsAlloc: Decompressor successfully allocated\n");

  s->cmode = cmode;

  return s;

out_free:
  kfree(s);
  MOD_DEC_USE_COUNT;
  return NULL;
}

/* Alloc space for a compressor - number of histories is known here */

static void *lzsCompAlloc(void *state, unsigned char *options, int opt_len,
			  int unit, int opthdr, int debug)
{
  u8 cmode;
  u16 nhists;
  LZSState *s;

  if (options[0] != CI_LZS_COMPRESS || options[1] != 3)
    return NULL;

  /* We need 2 configuration options: The number of histories and the
     check mode to use. The number is a short - we pass it in big endian */

  nhists = (options[2] << 8) | options[3];
  cmode = options[4];

  if (debug)
    printk(KERN_DEBUG "lzsCompAlloc: hists %d cmode %d\n", nhists, cmode);

  if (cmode > LZS_CMODE_EXT || cmode == LZS_CMODE_CRC || cmode == LZS_CMODE_LCB)
  {
    printk(KERN_WARNING "lzsCompAlloc: cmode %d not supported (yet)\n", cmode);
    return NULL;
  }

  /* Allocate the state */

  s = (LZSState *) kmalloc(sizeof(LZSState), GFP_KERNEL);
  if (!s)
    return NULL;

  memset(s, 0, sizeof(LZSState));

  /* A compressor is needed.  */
  if (debug)
    printk(KERN_DEBUG "lzsAlloc: Allocating compressor\n");
  s->comp = 1;
  if (comp)
  {
    s->hmode = LZS_HMODE_ONE;
    switch (nhists)
    {
    case 0:
      s->hmode = LZS_HMODE_TRASH;
/* We still need a hist here _during_ the packet compression */
/* This branch intentionally falls through */
    case 1:
      s->h = allocHists(1, s->comp);
      if (!s->h)
      {
	printk(KERN_WARNING "lzsAlloc: comp history - out of mem\n");
	kfree(s);
	return NULL;
      }
      break;
    default:
      s->hmode = LZS_HMODE_MANY;
      s->h = allocHists(nhists, s->comp);
      if (!s->h)
      {
	printk(KERN_WARNING "lzsAlloc: comp %d histories - out of mem\n", nhists);
	kfree(s);
	return NULL;
      }
      break;
    }
    if (debug)
      printk(KERN_DEBUG "lzsAlloc: Compressor successfully allocated\n");
  }
  else
  {
    printk(KERN_DEBUG "lzsAlloc: No allocations (compressor disabled)\n");
  }

  s->cmode = cmode;

  MOD_INC_USE_COUNT;

  return s;
}

static void lzsFree(void *state)
{
  LZSState *s = (LZSState *) state;

  if (s)
  {
    if (s->h)
    {
      if (debug)
	printk(KERN_DEBUG "lzsFree: freeing %d histories\n", s->h->nhists);
      freeHists(s->h);
    }
    if (debug)
      printk(KERN_DEBUG "lzsFree: freeing state\n");
    kfree(s);

    MOD_DEC_USE_COUNT;

  }
}

static int lzsInit(void *state, struct isdn_ppp_comp_data *data, int unit,
		   int debug)
{
  u16 nhists;
  u8 cmode;
  LZSState *s = (LZSState *) state;

  /* Mostly NYI (what the heck is it good for actually ?) */

  nhists = (data->options[0] << 8) | data->options[1];
  cmode = data->options[2];

  if (debug)
    printk(KERN_DEBUG "lzsInit: hists %d cmode %d\n", nhists, cmode);

  s->unit = unit;

  return 1;
}

/* Compression stuff starts here, helper functions first */

/* An index is valid if it is in the current range of the history */
static int __inline validIndex(LZSHist * h, u32 ix)
{
  return ((ix < h->head) && (ix >= (h->head - h->hlen)));
}

/* Add a new 2-byte-sequence to our hash infrastructure */
static void __inline addhash(LZSHist * h)
{
  /* We will go to next[h->head - 1] because we have a fixed mapping */
  register int index = (h->head - 1) & LZS_HISTORY_MASK;
  register u8 hash;
  register u8 *p;

  hash = 0;
  p = &h->hist[index];
  /* We can run through thanks to the 8-buffer (history mirror) */
  hash = HASHME(*p++, hash);
  hash = HASHME(*p, hash);

  /* Loop ourselfs into the current hash chain for hash */
  h->next[index] = h->hashtab[hash];
  h->hashtab[hash] = h->head - 1;
}

/* Zap one byte over to the history */
static void __inline putHistByte(LZSHist * h, u8 byte)
{
  int hix = h->head & LZS_HISTORY_MASK;
  /* Feed the real history */
  h->hist[hix] = byte;
  /* Feed the mirror history (8-buffer) */
  h->hist[hix + LZS_HISTORY_SIZE] = byte;
  /* Increase valid range. Actually, the valid range is 2048. If the hist
     is full, head points to the location where the next byte will be written
     but this location still contains the oldest byte in the history. We
     just ignore this fact, for a simple reason: we cannot encode an offset
     of 2048. When we cannot encode it, it makes no sense to look if a match
     is there at offset 2048, and the oldest one we care about is 2047. */
  if (h->hlen < (LZS_HISTORY_SIZE - 1))
    h->hlen++;
  if (h->hlen > 1)
  {
    /* We have at least 2 bytes starting at head-1 - add a hash table
       entry for them */
    addhash(h);
  }

  /* Move scope forward */
  h->head++;

  /* We just incremented and next check whether the value became zero.
     This should optimize to a single branch-equal on any decent pro-
     cessor. But x86 can always surprise you ... */

  /* Did we wrap around our index space ? */
  if (!(h->head))
  {
    /* We wrapped. It is very unlikely but still possible for us to find
       entries in the hash table that are left over from a former trip
       through index space. Make sure they are wiped out. */
    h->head = 2048;
    h->hlen = 0;
    memset(h->hashtab, 0, sizeof(u32) * LZS_HASHTAB_SIZE);
  }
}

/* Shift multiple bytes from inbuf to the history */
static void __inline putHistBytes(LZSHist * h, u8 * buf, int len)
{
  while (len--)
    putHistByte(h, *buf++);
}

/* Put some bits onto the output stream */
static void __inline putBits(LZSState * s, struct sk_buff *skbout, u32 bits,
			     int len)
{
  u8 byte;

  s->word <<= len;
  s->word |= bits;
  s->left += len;
  while (s->left >= 8)
  {
    s->left -= 8;
    byte = s->word >> (s->left);
    if (skb_tailroom(skbout) > 0)
      *(skb_put(skbout, 1)) = byte;
    else
      printk(KERN_WARNING "lzsComp: output skb full - truncated\n");
  }
}

static void __inline putLiteralByte(LZSState * s, struct sk_buff *skbout,
				    u8 byte)
{
  putBits(s, skbout, 0, 1);
  putBits(s, skbout, byte, 8);
}

static void __inline putCompressedString(LZSState * s, LZSHist * h,
					 struct sk_buff *skbout,
					 u32 index, int len)
{
  u32 offs = (h->head - index) & LZS_HISTORY_MASK;

  if (offs < 128)
  {
    /* Deploy a seven bit offset */
    putBits(s, skbout, 3, 2);
    putBits(s, skbout, offs, 7);
  }
  else
  {
    /* Deploy an eleven bit offset */
    putBits(s, skbout, 2, 2);
    putBits(s, skbout, offs, 11);	/* Blender is now 32bit */
  }

  switch (len)
  {
  case 2:
    putBits(s, skbout, 0, 2);
    break;
  case 3:
    putBits(s, skbout, 1, 2);
    break;
  case 4:
    putBits(s, skbout, 2, 2);
    break;
  case 5:
    putBits(s, skbout, 12, 4);
    break;
  case 6:
    putBits(s, skbout, 13, 4);
    break;
  case 7:
    putBits(s, skbout, 14, 4);
    break;
  default:
    len -= 8;
    putBits(s, skbout, 15, 4);
    while (len >= 15)
    {
      putBits(s, skbout, 15, 4);
      len -= 15;
    }
    putBits(s, skbout, len, 4);
  }
}

/* Return actual length of a match (new optimized version) */
static int __inline getMatchLength(LZSState * s, LZSHist * h, u32 ix, int minlen)
{
  register int len = 0;
  register int tlen;
  register u8 *inbuf = s->inbuf;
  register u8 *hbuf;

  /* We return the length of a match between the input buffer and the
     history at index ix provided that the length of this match is at
     least minlen. If it isn't, the caller doesn't care about the actual
     value and we can return 0. This allows us to call memcmp(3) for
     a more performant test. */

  /* Constrain our test to the number of relevant bytes */
  tlen = h->head - ix;
  tlen = compparms[comp][1] < tlen ? compparms[comp][1] : tlen;
  tlen = s->inlen < tlen ? s->inlen : tlen;

  if (tlen < minlen)
    /* Won't give a longer match anyway - ignore */
    return 0;

  /* Get start position in our history */
  hbuf = &h->hist[ix & LZS_HISTORY_MASK];

#ifdef LZS_MEMCMP_THRESHOLD
  /* We use memcmp(3) at all */
#if LZS_MEMCMP_THRESHOLD
  /* We use it only when the minlen exceeds a threshold */

  if (minlen > LZS_MEMCMP_THRESHOLD)
  {

#endif /* LZS_MEMCMP_THRESHOLD */

    /* If the two strings are not equal up to minlen, there will be no longer
       match than minlen and we can return 0 as well. */
    if (memcmp(hbuf, inbuf, minlen))
      return 0;

    /* Ok, they are equal so far - the rest is done as usual */
    hbuf += minlen;
    inbuf += minlen;
    tlen -= minlen;
    len += minlen;
    /* Seen the overhead above ? Together with general call overhead, this is
       why we are using a threshold for really calling memcmp(3). Some archi-
       tectures use memcmp(3) implementations that perform great, but need
       at least a long- or even octaword to actually show up with a gain. */

#if LZS_MEMCMP_THRESHOLD

  }

#endif /* LZS_MEMCMP_THRESHOLD */
#endif /* defined(LZS_MEMCMP_THRESHOLD) */

  while (tlen-- && (*hbuf++ == *inbuf++))
    len++;

  return len;
}

static int lzsCompress(void *state, struct sk_buff *skbin,
		       struct sk_buff *skbout, int proto)
{
  /* The heart of the compression is here */

  register LZSState *s = (LZSState *) state;
  register LZSHist *h;

  u16 hi = 0;
  u8 *p;
  register int llen, nlen, retry;
  register u32 hidx, lidx, next;
  register u8 hash;
  int prepd, ohlen, totlen, ext, ilen, cols;
  u8 *ibuf;

  /* Prefill statistics for the case of sending uncompressed - this will then
     be used if any of the following return 0 statements hit */

  s->stats.in_count += skbin->len + 2;
  s->stats.bytes_out += skbin->len + 2;
  s->stats.inc_bytes += skbin->len + 2;
  s->stats.inc_packets++;

  if (!comp)
  {
    if (debug > 1)
      printk(KERN_DEBUG "lzsComp: leaving as is\n");
    return 0;
  }

  if (proto < 0x21 || proto > 0xf9 || !(proto & 0x1))
  {
    printk(KERN_DEBUG "lzsComp: called with %04x\n", proto);
    return 0;
  }

  /* Step 1 - verify the output skb is large enough to eat our output. We
     just statically verify that the tailroom can stand the maximum ex-
     pansion of the input data. */
  if (skb_tailroom(skbout) < ((skbin->len + 4) + ((skbin->len + 2) >> 3)))
  {
    printk(KERN_WARNING "lzsComp: out skb tailroom too small\n");
    return 0;
  }

  /* Step 2 - verify the output skb can receive the data we need to pre-
     pend to the compressed stuff. */
  ohlen = 0;
  switch (s->hmode)
  {
  case LZS_HMODE_MANY:
    if (s->h->nhists > 255)
      ohlen += 2;
    else
      ohlen++;
    break;
  default:
    /* Nothing to do - history is not sent explicitely */
  }

  switch (s->cmode)
  {
  case LZS_CMODE_NONE:
    /* Nothing */
    break;
  case LZS_CMODE_SEQNO:
    /* One byte */
    ohlen++;
    break;
  case LZS_CMODE_EXT:
    /* Two bytes */
    ohlen += 2;
    break;
  case LZS_CMODE_LCB:
  case LZS_CMODE_CRC:
  default:
    /* Still to be implemented */
    printk(KERN_WARNING "lzsComp: cmode %d NYI (sending as is)\n", s->cmode);
    return 0;
  }

  if (skb_headroom(skbout) < ohlen)
  {
    printk(KERN_WARNING "lzsComp: out skb headroom insufficient\n");
    return 0;
  }

  /* Step 3 - initialize some values for compression */
  hi = 1;
  h = &s->h->hists[hi - 1];
  s->word = s->left = 0;

  /* Frames always start with the protocol. However, the input sk_buff does
     not start with these two bytes. We instead get them communicated by
     proto, and will first compress them. This has the drawback that we
     cannot easily feed them to our compression engine, while they are
     a very probable start of a sequence. We try whether we can temporarily
     prepend them to the input skb, or if not just output them literal to
     have something to start with. */

  /* Step 4 - try to prepend the proto to skbin if possible */
  if (skb_headroom(skbin) > 1)
  {
    p = skb_push(skbin, 2);
    *p++ = proto >> 8;
    *p = proto & 0xff;
    prepd = 1;
  }
  else
  {
    putLiteralByte(s, skbout, proto >> 8);
    putHistByte(h, proto >> 8);
    putLiteralByte(s, skbout, proto & 0xff);
    putHistByte(h, proto & 0xff);
    prepd = 0;
  }

  /* Step 5 - the actual compression code. Don't beat me. */

  /* Start by setting our input area */

  s->inbuf = skbin->data;
  s->inlen = skbin->len;

  while (s->inlen)
  {
    /* More bytes to consume */
    if (h->hlen < 2 || (s->inlen == 1))
    {
      /* No history to search so far or just one more byte anyway */
      putLiteralByte(s, skbout, *s->inbuf);
      putHistByte(h, *s->inbuf);
      s->inlen--;
      s->inbuf++;
      continue;
    }
    /* Ok, we have at least 2 bytes in the history and at least two still to
       be read. So we can start to search our hash infrastructure for this
       particular 2-byte-sequence */
    hash = 0;
    hash = HASHME(s->inbuf[0], hash);
    hash = HASHME(s->inbuf[1], hash);
    hidx = h->hashtab[hash];
    if (validIndex(h, hidx))
    {
      /* Seems to be something valid in the hash table. May, however, be a
         hash clash. */
      /* Where to try next */
      next = h->next[hidx & LZS_HISTORY_MASK];
      /* Where this supposed match starts */
      lidx = hidx;
      /* How long it is - if it is a clash, it is 0 or 1 bytes long */
      llen = 0;
      nlen = getMatchLength(s, h, lidx, llen + 1);
      if (nlen > llen)
	llen = nlen;
      /* Is this already the best possible (remaining) match ? */
      if (llen == s->inlen || llen >= compparms[comp][1])
      {
	/* Yeah. Just spit it out */
	putCompressedString(s, h, skbout, lidx, llen);
	putHistBytes(h, s->inbuf, llen);
	s->inlen -= llen;
	s->inbuf += llen;
	continue;
      }
      retry = compparms[comp][0];
      while (validIndex(h, next) && retry--)
      {
	/* Traverse this hash chain and find the longest match on it */
	hidx = next;
	/* Climb forward */
	next = h->next[hidx & LZS_HISTORY_MASK];
	/* Try to find a longer match */
	nlen = getMatchLength(s, h, hidx, llen + 1);
	if (nlen > llen)
	{
	  lidx = hidx;
	  llen = nlen;
	  /* Found the best possible match ? */
	  if (llen == s->inlen || llen >= compparms[comp][1])
	  {
	    break;
	  }
	}
      }
      /* Well, if me made it till here the longest match we found is in
         lidx/llen. Do the right thing with it. */
      if (llen > 1)
      {
	/* Nice, got a sequence match */
	putCompressedString(s, h, skbout, lidx, llen);
	putHistBytes(h, s->inbuf, llen);
	s->inlen -= llen;
	s->inbuf += llen;
      }
      else
      {
	/* Just zap a literal byte and start over */
	putLiteralByte(s, skbout, *s->inbuf);
	putHistByte(h, *s->inbuf);
	s->inlen--;
	s->inbuf++;
      }
    }
    else
    {
      /* Never seen this sequence, zap this byte and try with the next */
      putLiteralByte(s, skbout, *s->inbuf);
      putHistByte(h, *s->inbuf);
      s->inlen--;
      s->inbuf++;
    }
  }
  /* Write the end marker - it is a 7 bit offset of zero */
  putBits(s, skbout, 0x180, 9);
  /* Flush last bits */
  putBits(s, skbout, 0, 8);

  /* Step 6 - revert prepended proto if it exists */
  if (prepd)
    skb_pull(skbin, 2);

  /* Step 7 - decision time. We have compressed the data and know the final
     size of the frame to be sent. We must decide whether we want to send
     the frame compressed or not. This is not as simple as it seems, espe-
     cially because a single frame that expands a bit may help later frames
     to compress. We use this heuristics for now:
     a) If the final frame exceeds the MTU, it cannot be sent compressed.
     b) If the frame expands somewhat and it is the first frame that does
     expand, send it compressed. Maybe we gain better compression on
     later frames this way.
     c) If the frame expands and the former one did so as well, we send
     it uncompressed.

     Note that we do not use the inband sending method of uncompressed
     data of the EXT mode. This is a rather Micro$oftish nonsense which
     just shows the particular inability of reading a standard paper by
     these guys. If you want to send uncompressed, just do it - it is that
     simple.
   */

  totlen = ohlen + skbout->len;

  /* HACK Attack Warning - this looks weird. Would really be nice to have
     the real MTU here. But I don't have a way to find it out. Seems that
     another API change would be necessary to allow for this. On the other
     hand, the MTU is never set or used by the isdn_ppp stuff, the ioctl(2)
     for that job doesn't do anything. Thus, to have something to try with
     at all, assume MTU is 1500 fixed. HACK anyway. */

  if ((totlen + 4) > 1500)
  {
    if (debug > 1)
      printk(KERN_DEBUG "lzsComp: compressed size exceeds MTU\n");
    resetCompHist(s, h);
    s->lastinc = 1;
    return 0;
  }

  if (totlen > skbin->len)
  {
    if (s->lastinc)
    {
      if (debug > 1)
	printk(KERN_DEBUG "lzsComp: repeated incompressible frames\n");
      resetCompHist(s, h);
      return 0;
    }
    s->lastinc = 1;
  }
  else
  {
    s->lastinc = 0;
  }

  /* Step 8 - fill the remaining parts of the frame by prepending them to
     the skbout. Return the frame length so it can be sent. */

  p = skb_push(skbout, ohlen);

  /* Emit the history number. It is only present if greater than one, and
     it is transmitted as 1 or 2 bytes, depending on the number of histories
     negotiated */

  switch (s->hmode)
  {
  case LZS_HMODE_TRASH:
  case LZS_HMODE_ONE:
    /* We do not need to send one. It is implicitly 1. */
    break;
  case LZS_HMODE_MANY:
    if (s->h->nhists > 255)
    {
      /* A 16 bit history number */
      *p++ = LZS_HIST_BYTE1(hi);
      *p++ = LZS_HIST_BYTE2(hi);
    }
    else
    {
      /* An 8 bit history number */
      *p++ = hi;
    }
    break;
  }

  /* The next thing to send is the checkmode specific data */

  switch (s->cmode)
  {
  case LZS_CMODE_NONE:
    /* Nothing to be sent for this */
    break;
  case LZS_CMODE_SEQNO:
    /* Default mode. Emit a one-byte per-history sequence number. */

#ifdef TEST_COMP_BROKEN_SEQNO
    if (h->seqno == TEST_COMP_BROKEN_SEQNO)
    {
      *p++ = h->seqno - 1;
      h->seqno++;
    }
    else
      *p++ = h->seqno++;
#else
    *p++ = h->seqno++;
#endif

    break;
  case LZS_CMODE_EXT:
    /* We need to emit a 16bit word with 2 relevant flagbits and a 12 bit
       coherency counter. */
    ext = s->ccnt;

#ifdef TEST_COMP_BROKEN_CCNT
    if (ext == TEST_COMP_BROKEN_CCNT)
      ext--;
#endif

    s->ccnt++;
    s->ccnt &= 0x0fff;
    /* Mark the frame as compressed by setting bit C */
    ext |= 0x2000;
    if (s->ackrs)
    {
      /* Mark the frame as an inband reset ack by setting bit A */
      ext |= 0x8000;
      s->ackrs = 0;
    }
    *p++ = ext >> 8;
    *p++ = ext & 0xff;
    break;
  case LZS_CMODE_LCB:
  case LZS_CMODE_CRC:
  default:
    /* Still to be implemented */
    printk(KERN_WARNING "lzsComp: cmode %d NYI (sending as is)\n", s->cmode);
    return 0;
  }

  if (debug > 1)
    printk(KERN_DEBUG "lzsComp: %d in %d out - sending compressed\n",
	   skbin->len, skbout->len);
  if (debug > 2)
  {
    printk(KERN_DEBUG "lzsComp packet in:\n");

    ilen = skbin->len;
    ibuf = skbin->data;
    cols = 0;

    while (ilen--)
    {
      if (!(cols % 16))
      {
	printk(KERN_DEBUG "[%04x]", cols);
      }
      printk(" %02x", *ibuf++);
      cols++;
      if (!(cols % 16) || !ilen)
      {
	printk("\n");
      }
    }
    printk(KERN_DEBUG "\n");

    printk(KERN_DEBUG "lzsComp packet out:\n");

    ilen = skbout->len;
    ibuf = skbout->data;
    cols = 0;

    while (ilen--)
    {
      if (!(cols % 16))
      {
	printk(KERN_DEBUG "[%04x]", cols);
      }
      printk(" %02x", *ibuf++);
      cols++;
      if (!(cols % 16) || !ilen)
      {
	printk("\n");
      }
    }
    printk(KERN_DEBUG "\n");
  }

  /* Adapt statistics - correct the former assumption of an incompressible
     packet by tweaking the counters */

  s->stats.inc_bytes -= skbin->len + 2;
  s->stats.inc_packets--;

  s->stats.bytes_out -= skbin->len + 2;
  s->stats.bytes_out += skbout->len;

  s->stats.comp_bytes += skbout->len;
  s->stats.comp_packets++;

  return skbout->len;
}

static void lzsIncomp(void *state, struct sk_buff *skbin, int proto)
{
  /* If I understand it correctly this one is called when the peer has
     sent a frame without compression (an incompressable one). We will
     update the history with the data in order to keep it in sync with
     the sender. It does not make any difference whether the sender knows
     about this, a property of LZS is that the decompressor is pretty
     selfcontained. */

  /* Actually, the RFC states that a compressor transmitting an uncom-
     pressed frame MUST reset his history, thus per the RFC it would be
     completely irrelevant whether we feed back incomps or not. But
     worse I get VJ errors when feeding back (should not happen) and much
     less errors when not feeding back - something is wrong here (may
     be with may peer). Deactivated feedback so far. */

  register LZSState *s = (LZSState *) state;

#if 0

  int ilen, cols;
  u8 *ibuf;
  register LZSHist *h;


  ibuf = skbin->data;
  ilen = skbin->len;

  /* FIXME */
  h = &s->h->hists[0];

  /* Just fluff over all bytes into the history. The pitfall is that the
     compressor has generated his history with the frame _including_ the
     PPP proto bytes while our skb points behind them. We regenerate the
     two bytes from the proto argument, using big endian (as always) */

  h->hist[h->head++] = proto >> 8;
  h->head &= LZS_HISTORY_MASK;
  h->hist[h->head++] = proto & 0xff;
  h->head &= LZS_HISTORY_MASK;

  while (ilen--)
  {
    h->hist[h->head++] = *ibuf++;
    h->head &= LZS_HISTORY_MASK;
  }

#ifdef HEAVY_DEBUG
  printk(KERN_DEBUG "lzsIncomp: packet in:\n");

  /* Dump the frame for decomp experiments */

  ilen = skbin->len;
  ibuf = skbin->data;
  cols = 0;

  while (ilen--)
  {
    if (!(cols % 16))
    {
      printk(KERN_DEBUG "[%04x]", cols);
    }
    printk(" %02x", *ibuf++);
    cols++;
    if (!(cols % 16) || !ilen)
    {
      printk("\n");
    }
  }
  printk(KERN_DEBUG "\n");
#endif /* HEAVY_DEBUG */
#endif /* 0 */

  s->stats.inc_bytes += skbin->len;
  s->stats.inc_packets++;

  s->stats.in_count += skbin->len;
  s->stats.bytes_out += skbin->len;

}

/* Decompression stuff actually starting here. I'm not that proud of it
   because it will not compile to highly efficient code. I've tried around
   a bit with other paradigms (macros, inline functions with lots of pointer
   parameters for all state variables) and they were unreadable. The current
   one is a compromise of readability and efficiency, not the less because
   efficiency is very processor specific (on decent processors you want
   to utilize the whole register file for temporaries and do a lot to let
   the optimizer find out how - but the x86 register file is a bad joke and
   actually replaced by a quite fast L1 cache so keeping state in a small
   struct is probably faster here - keeping more than four longs of state
   in registers would only lead to register thrashing [give me back my 68k]).
   Code like this should be written in assembly anyway ;) */

/* Get one bit from the skb */
static __inline u32 get1(LZSState * s)
{
  register u8 byte;
  register u32 ret;

  if (s->left == 0)
  {
    /* Not a single bit left - get a new byte */
    if (s->inlen)
    {
      byte = *s->inbuf++;
      s->inlen--;
      s->word |= (byte << 8);
      s->left = 8;
    }
    else
    {
      if (s->zstuff > 0)
      {
	printk(KERN_INFO "lzsDecomp: Warning: stuffing zeros\n");
	s->zstuff++;
      }
      else
      {
	s->zstuff = 1;
      }
    }
  }
  ret = s->word & 0x8000;
  s->word <<= 1;
  s->left--;
  return ret;
}

/* Common getbyte code - not used above because it is a bit more complicated
   than the case above and get1 is called really often */

static __inline void pullByte(LZSState * s)
{
  register u8 byte;

  if (s->inlen)
  {
    byte = *s->inbuf++;
    s->inlen--;
    s->word |= (byte << (8 - s->left));
    s->left += 8;
  }
  else
  {
    /* TODO: Fix zero stuffing */
    if (s->zstuff > 0)
    {
      printk(KERN_INFO "lzsDecomp: Warning: stuffing zeros\n");
      s->zstuff++;
    }
    else
    {
      s->zstuff = 1;
    }
  }
}

/* Get two bits */

static __inline u32 get2(LZSState * s)
{
  register u32 ret;

  if (s->left < 2)
    /* Not enough bits left - get a new byte */
    pullByte(s);
  ret = s->word & 0xc000;
  s->word <<= 2;
  s->left -= 2;
  return ret;
}

/* Get four bits */

static __inline u32 get4(LZSState * s)
{
  register u32 ret;

  if (s->left < 4)
    /* Not enough bits left - get a new byte */
    pullByte(s);
  ret = s->word & 0xf000;
  s->word <<= 4;
  s->left -= 4;
  return ret;
}

/* Get seven bits */

static __inline u32 get7(LZSState * s)
{
  register u32 ret;

  if (s->left < 7)
    /* Not enough bits left - get a new byte */
    pullByte(s);
  ret = s->word & 0xfe00;
  s->word <<= 7;
  s->left -= 7;
  return ret;
}

/* Get eight bits */

static __inline u32 get8(LZSState * s)
{
  register u32 ret;

  if (s->left < 8)
    /* Not enough bits left - get a new byte */
    pullByte(s);
  ret = s->word & 0xff00;
  s->word <<= 8;
  s->left -= 8;
  return ret;
}

/* Get eleven bits - we just get 7 and then another 4 or we had to code
   this explicitely */

static __inline u32 get11(LZSState * s)
{
  register u32 ret;

  ret = get7(s);
  ret |= get4(s) >> 7;

  return ret;
}

/* Get the compressed length value from the input stream */

static __inline short getCompLen(LZSState * s)
{
  register int clen, nibble;
  /* The most probable cases are hardwired */
  switch (get2(s))
  {
  case 0x0000:
    return 2;
  case 0x4000:
    return 3;
  case 0x8000:
    return 4;
  default:
    switch (get2(s))
    {
    case 0x0000:
      return 5;
    case 0x4000:
      return 6;
    case 0x8000:
      return 7;
    default:
      /* Ok, no shortcuts anymore - just get nibbles and add up */
      clen = 8;
      do
      {
	nibble = get4(s) >> 12;
	clen += nibble;
	/* If we find enough nibbles to wrap something went really wrong. Or
	   not ? Actually, lengths > 2048 could be pretty Ok, if compressing
	   any data stream that is repetitive on a 2^n basis and very long,
	   the compressor could theoretically issue a very long self-reference
	   so we eventually need to remove this protection. If anyone ever sees
	   this happen, I was too german about that. */
	if (clen > LZS_HISTORY_SIZE)
	  return 0;
      }
      while (nibble == 0xf);
      return clen;
    }
  }
}

/* Output one byte to history and outbuffer */

static __inline void byteOut(LZSState * s, LZSHist * h, struct sk_buff *skbout,
			     u8 byte)
{
  h->hist[h->head++] = byte;
  h->head &= LZS_HISTORY_MASK;
  if (skb_tailroom(skbout) > 0)
    *(skb_put(skbout, 1)) = byte;
  else
    printk(KERN_WARNING "lzsDecomp: output skb full - truncated\n");
}

/* Output a bytestream referenced in the history by offs & clen */

static __inline void copyComp(LZSState * s, LZSHist * h, struct sk_buff *skbout,
			      int offs, int clen)
{
  register int hpos = h->head - offs;

  hpos &= LZS_HISTORY_MASK;
  while (clen--)
  {
    byteOut(s, h, skbout, h->hist[hpos]);
    hpos++;
    hpos &= LZS_HISTORY_MASK;
  }
}

static int lzsDecompress(void *state, struct sk_buff *skbin,
			 struct sk_buff *skbout,
			 struct isdn_ppp_resetparams *rsparm)
{
  /* Ahh. We finally got where the interesting stuff sits */

  int ilen, cols;
  u8 *ibuf;

  register int offs, clen;
  register LZSState *s = (LZSState *) state;
  register LZSHist *h;
  u16 hi = 0;
  u8 seqno;
  u16 ccnt;

  /* Start by setting our read area */

  s->inbuf = skbin->data;
  s->inlen = skbin->len;

  /* Prepare the reset parameters for use */
  rsparm->valid = 1;
  rsparm->rsend = 1;
  rsparm->idval = 1;
  rsparm->id = s->rsid;

  /* The first option, if present, is the history number to decompress
     this frame against. Note that histories are counted starting at 1,
     while our array indexing is zero based. */

  switch (s->hmode)
  {
  case LZS_HMODE_TRASH:
  case LZS_HMODE_ONE:
    /* No history number in frame. History #1 is implicit */
    hi = 1;
    break;
  case LZS_HMODE_MANY:
    /* History is at the frame top. Either one or two bytes */
    if (s->inlen)
    {
      hi = *s->inbuf++;
      s->inlen--;
      if (s->h->nhists > 255)
      {
	/* Two byte history number */
	if (s->inlen)
	{
	  hi <<= 8;
	  hi |= *s->inbuf++;
	  s->inlen--;
	}
	else
	{
	  return DECOMP_ERROR;
	}
      }
    }
    else
    {
      return DECOMP_ERROR;
    }
    break;
  }

  h = &s->h->hists[hi - 1];

  /* We do now know the most relevant parameter to the Reset-Request. Decide
     whether we tack it on. We usually do so only if it is necessary aka
     not one, or if tweak flags tell us it would be better. */

  if (rsparm->maxdlen >= 2 &&
      ((s->cmode == LZS_CMODE_SEQNO && hi == 1 &&
	(tweak & LZS_TW_M3_RSRQ_EXP_HIST)) || (hi != 1)))
  {
    rsparm->dlen = 2;
    rsparm->data[0] = (hi >> 8);
    rsparm->data[1] = (hi & 0xff);
    rsparm->dtval = 1;
  }

  /* The second option, if present, is the check item according to the
     check mode negotiated for this state */
  switch (s->cmode)
  {
  case LZS_CMODE_NONE:
    /* Very dumb mode. Will likely go boom if sneezed onto */
    break;
  case LZS_CMODE_SEQNO:
    /* Default mode. Next byte is a sequence number. Check this out */
    if (s->inlen)
    {
      seqno = *s->inbuf++;
      s->inlen--;
    }
    else
    {
      return DECOMP_ERROR;
    }

#ifdef TEST_BROKEN_SEQNO
    if (seqno == TEST_BROKEN_SEQNO)
      seqno++;
#endif

    if (seqno != h->seqno)
    {
      /* We did not expect _that_ sequence number */
      if (debug)
	printk(KERN_DEBUG "lzsDecomp: rcvd seq# %d exp seq# %d (sync lost)\n",
	       seqno, h->seqno);
      /* We MUST resync on seqno+1 */
      seqno++;
      h->seqno = seqno;
      /* We have an outstanding reset ack now */
      rsparm->expra = 1;
      h->expra = 1;
      /* We expect the Ack to have this id (which we stuff into the Req) */
      h->rsid = s->rsid;
      return DECOMP_ERROR;
    }
    else
    {
      /* Correct seqno got - expect the next one */
      h->seqno++;
      /* Are we really resynced or is a reset ack still outstanding ? */
      if (h->expra)
      {
	if (debug)
	  printk(KERN_DEBUG "lzsDecomp: rcvd seq# %d but missing ResetAck\n", seqno);
	/* Error again */
	rsparm->expra = 1;
	return DECOMP_ERROR;
      }
    }
    break;

  case LZS_CMODE_EXT:
    /* The next 16 bit contain the 4 flagbits of which 2 are actually used and
       the 12 bit coherency counter (another sequence number, that is). */

    rsparm->expra = 0;		/* Ext mode uses inband signaling - no Acks */

    if (tweak & LZS_TW_M4_RSRQ_NO_HIST)
      /* Should be default, but make it sure finally */
      rsparm->dtval = rsparm->dlen = 0;

    if (s->inlen > 1)
    {
      ccnt = (*s->inbuf++ << 8);
      ccnt |= *s->inbuf++;
      s->inlen -= 2;
    }
    else
    {
      return DECOMP_ERROR;
    }

#ifdef TEST_BROKEN_CCNT
    if ((ccnt & 0x0fff) == TEST_BROKEN_CCNT)
      ccnt++;
#endif

    if ((ccnt & 0x0fff) != s->ccnt)
    {
      /* Coherency count out of sequence */
      if (ccnt & 0x8000)
      {
	/* Bit A is set - this is an inband reset-ack and we resync our coherency
	   counter with the one supplied */
	s->ccnt = (ccnt & 0x0fff);
	if (debug)
	  printk(KERN_DEBUG "lzsDecomp: coherency resync on %03x\n", ccnt & 0x0fff);
	/* Make sure the next error uses a new id - this was an ack */
	s->rsid++;
      }
      else
      {
	/* We are indeed out of sync */
	if (debug)
	  printk(KERN_DEBUG "lzsDecomp: coherency %03x expected %03x (sync lost)\n",
		 ccnt & 0x0fff, s->ccnt);
	return DECOMP_ERROR;
      }
    }
    /* We expect the next coherency counter */
    s->ccnt++;
    s->ccnt &= 0x0fff;
    if (!(ccnt & 0x2000))
    {
      /* Bit C indicates the frame is not compressed - push it out */
      if (debug)
	printk(KERN_DEBUG "lzsDecomp: uncompressed frame passed through\n");
      if (skb_tailroom(skbout) >= s->inlen)
      {
	memcpy(skb_put(skbout, s->inlen), s->inbuf, s->inlen);

	s->stats.inc_bytes += s->inlen;
	s->stats.inc_packets++;
	s->stats.in_count += s->inlen;
	s->stats.bytes_out += s->inlen;

	return s->inlen;
      }
      else
      {
	printk(KERN_WARNING "lzsDecomp: uncompressed frame dropped (out of mem)\n");
      }
    }
    break;

  case LZS_CMODE_LCB:
  case LZS_CMODE_CRC:
  default:
    /* Still to be implemented */
    printk(KERN_WARNING "lzsDecomp: cmode %d NYI (CCP teardown)\n", s->cmode);
    return DECOMP_FATALERROR;
  }

  /* The real decompression code. Looks quite simple ? */

  /* Initialize for decomp */
  s->word = s->left = s->zstuff = 0;

  for (;;)
  {
    if (s->zstuff > 1)
    {
      printk(KERN_WARNING "lzsDecomp: missing end marker - cooked one\n");
      break;
    }
    if (get1(s))
    {
      /* Compressed bytes follow */
      if (get1(s))
      {
	/* Seven bit offset follows */
	offs = get7(s) >> 9;
	if (!offs)
	  /* This is the end marker - a 7 bit offset of zero */
	  break;
	/* You see the error message down there ? You actually think it is
	   nonsense ? Look up my comment at getCompLen() and give me a hint on
	   what you find out. */
	if (!(clen = getCompLen(s)))
	{
	  printk(KERN_WARNING "lzsDecomp: length hosed - dropped\n");
	  return DECOMP_ERROR;
	}
	copyComp(s, h, skbout, offs, clen);
      }
      else
      {
	/* Eleven bit offset follows */
	offs = get11(s) >> 5;
	if (!(clen = getCompLen(s)))
	{
	  printk(KERN_WARNING "lzsDecomp: length hosed - dropped\n");
	  return DECOMP_ERROR;
	}
	copyComp(s, h, skbout, offs, clen);
      }
    }
    else
    {
      /* Literal byte follows */
      byteOut(s, h, skbout, get8(s) >> 8);
    }
  }

  if (debug > 2)
  {
    printk(KERN_DEBUG "lzsDecomp packet in:\n");

    ilen = skbin->len;
    ibuf = skbin->data;
    cols = 0;

    while (ilen--)
    {
      if (!(cols % 16))
      {
	printk(KERN_DEBUG "[%04x]", cols);
      }
      printk(" %02x", *ibuf++);
      cols++;
      if (!(cols % 16) || !ilen)
      {
	printk("\n");
      }
    }
    printk(KERN_DEBUG "\n");

    printk(KERN_DEBUG "lzsDecomp packet out:\n");

    ilen = skbout->len;
    ibuf = skbout->data;
    cols = 0;

    while (ilen--)
    {
      if (!(cols % 16))
      {
	printk(KERN_DEBUG "[%04x]", cols);
      }
      printk(" %02x", *ibuf++);
      cols++;
      if (!(cols % 16) || !ilen)
      {
	printk("\n");
      }
    }
    printk(KERN_DEBUG "\n");
  }

  s->stats.comp_bytes += skbout->len;
  s->stats.comp_packets++;
  s->stats.in_count += skbin->len;
  s->stats.bytes_out += skbout->len;

  return skbout->len;
}

/*
 * Entry points of this shrinker
 */

struct compressor ppp_lzs_compress =
{
  CI_LZS_COMPRESS,		/* CCP proto for PPP */
  lzsAlloc,			/* Alloc new state */
  lzsFree,			/* Drop state */
  lzsInit,			/* Initialize state */
  lzsReset,			/* Reset state */
  lzsCompress,			/* Do the shrink */
  lzsStats,
  lzsDecompAlloc,
  lzsDecompFree,
  lzsDecompInit,
  lzsDecompReset,
  lzsDecompress,		/* Do the other thing */
  lzsIncomp,			/* Handle incompressible frame */
  lzsStats			/* Get stats */
};

/*
 * Module init: Register myself with the compressor list
 */

int init_module(void)
{
  int a = ppp_register_compressor(&ppp_lzs_compress);
  if (!a)
  {
    printk(KERN_INFO "PPP Stac/HiFn LZS (De)Compression registered\n");
    if (comp < 0 || comp > 9)
    {
      printk(KERN_ERR "lzs: 0 <= comp <= 9  - set to 0 (no compression)\n");
      comp = 0;
    }
  }
  return a;
}

/*
 * Module fini: Clear my traces
 */

void cleanup_module(void)
{
  ppp_unregister_compressor(&ippp_lzs_compress);
}
