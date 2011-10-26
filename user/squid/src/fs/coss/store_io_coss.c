
/*
 * $Id: store_io_coss.c,v 1.13.2.11 2005/03/26 23:40:21 hno Exp $
 *
 * DEBUG: section 79    Storage Manager COSS Interface
 * AUTHOR: Eric Stern
 *
 * SQUID Web Proxy Cache          http://www.squid-cache.org/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from
 *  the Internet community; see the CONTRIBUTORS file for full
 *  details.   Many organizations have provided support for Squid's
 *  development; see the SPONSORS file for full details.  Squid is
 *  Copyrighted (C) 2001 by the Regents of the University of
 *  California; see the COPYRIGHT file for full details.  Squid
 *  incorporates software developed and/or copyrighted by other
 *  sources; see the CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

#include "squid.h"
#include <aio.h>
#include "async_io.h"
#include "store_coss.h"

static DWCB storeCossWriteMemBufDone;
static DRCB storeCossReadDone;
static void storeCossIOCallback(storeIOState * sio, int errflag);
static char *storeCossMemPointerFromDiskOffset(SwapDir * SD, size_t offset, CossMemBuf ** mb);
static void storeCossMemBufLock(SwapDir * SD, storeIOState * e);
static void storeCossMemBufUnlock(SwapDir * SD, storeIOState * e);
static void storeCossWriteMemBuf(SwapDir * SD, CossMemBuf * t);
static void storeCossWriteMemBufDone(int fd, int errflag, size_t len, void *my_data);
static CossMemBuf *storeCossCreateMemBuf(SwapDir * SD, size_t start,
    sfileno curfn, int *collision);
static CBDUNL storeCossIOFreeEntry;
static off_t storeCossFilenoToDiskOffset(sfileno f, CossInfo *);
static sfileno storeCossDiskOffsetToFileno(off_t o, CossInfo *);
static void storeCossMaybeWriteMemBuf(SwapDir * SD, CossMemBuf * t);

static void membuf_describe(CossMemBuf * t, int level, int line);

CBDATA_TYPE(storeIOState);
CBDATA_TYPE(CossMemBuf);

/* === PUBLIC =========================================================== */

/*
 * This routine sucks. I want to rewrite it when possible, and I also think
 * that we should check after creatmembuf() to see if the object has a
 * RELEASE_REQUEST set on it (thanks Eric!) rather than this way which seems
 * to work..
 * -- Adrian
 */
static sfileno
storeCossAllocate(SwapDir * SD, const StoreEntry * e, int which)
{
    CossInfo *cs = (CossInfo *) SD->fsdata;
    CossMemBuf *newmb;
    off_t retofs;
    size_t allocsize;
    int coll = 0;
    sfileno checkf;

    /* Make sure we chcek collisions if reallocating */
    if (which == COSS_ALLOC_REALLOC) {
	checkf = e->swap_filen;
	coss_stats.alloc.realloc++;
    } else {
	checkf = -1;
	coss_stats.alloc.alloc++;
    }

    if (e->swap_file_sz > 0)
	allocsize = e->swap_file_sz;
    else
	allocsize = objectLen(e) + e->mem_obj->swap_hdr_sz;

    /* Since we're not supporting NOTIFY anymore, lets fail */
    assert(which != COSS_ALLOC_NOTIFY);

    /* Check if we have overflowed the disk .. */
    if ((cs->current_offset + allocsize) > ((off_t) SD->max_size << 10)) {
	/*
	 * tried to allocate past the end of the disk, so wrap
	 * back to the beginning
	 */
	coss_stats.disk_overflows++;
	cs->current_membuf->flags.full = 1;
	cs->current_membuf->diskend = cs->current_offset;
	storeCossMaybeWriteMemBuf(SD, cs->current_membuf);
	cs->current_offset = 0;	/* wrap back to beginning */
	debug(79, 2) ("storeCossAllocate: wrap to 0\n");

	newmb = storeCossCreateMemBuf(SD, 0, checkf, &coll);
	cs->current_membuf = newmb;

	/* Check if we have overflowed the MemBuf */
    } else if ((cs->current_offset + allocsize) >= cs->current_membuf->diskend) {
	/*
	 * Skip the blank space at the end of the stripe. start over.
	 */
	coss_stats.stripe_overflows++;
	cs->current_membuf->flags.full = 1;
	cs->current_offset = cs->current_membuf->diskend;
	storeCossMaybeWriteMemBuf(SD, cs->current_membuf);
	debug(79, 2) ("storeCossAllocate: New offset - %ld\n",
	    (long int) cs->current_offset);
	newmb = storeCossCreateMemBuf(SD, cs->current_offset, checkf, &coll);
	cs->current_membuf = newmb;
    }
    /* If we didn't get a collision, then update the current offset and return it */
    if (coll == 0) {
	retofs = cs->current_offset;
	cs->current_offset = retofs + allocsize;
	/* round up to our blocksize */
	cs->current_offset = ((cs->current_offset + cs->blksz_mask) >> cs->blksz_bits) << cs->blksz_bits;
	return storeCossDiskOffsetToFileno(retofs, cs);
    } else {
	coss_stats.alloc.collisions++;
	debug(79, 3) ("storeCossAllocate: Collision\n");
	return -1;
    }
}

void
storeCossUnlink(SwapDir * SD, StoreEntry * e)
{
    debug(79, 3) ("storeCossUnlink: offset %d\n", e->swap_filen);
    coss_stats.unlink.ops++;
    coss_stats.unlink.success++;
    storeCossRemove(SD, e);
}


storeIOState *
storeCossCreate(SwapDir * SD, StoreEntry * e, STFNCB * file_callback, STIOCB * callback, void *callback_data)
{
    CossState *cstate;
    storeIOState *sio;

    coss_stats.create.ops++;
    sio = cbdataAlloc(storeIOState);
    cstate = memPoolAlloc(coss_state_pool);
    sio->fsstate = cstate;
    sio->offset = 0;
    sio->mode = O_WRONLY | O_BINARY;

    /*
     * If we get handed an object with a size of -1,
     * the squid code is broken
     */
    assert(e->mem_obj->object_sz != -1);

    /*
     * this one is kinda strange - Eric called storeCossAllocate(), then
     * storeCossOpen(O_RDONLY) .. weird. Anyway, I'm allocating this now.
     */
    sio->st_size = objectLen(e) + e->mem_obj->swap_hdr_sz;
    sio->swap_dirn = SD->index;
    sio->swap_filen = storeCossAllocate(SD, e, COSS_ALLOC_ALLOCATE);
    debug(79, 3) ("storeCossCreate: offset %ld, size %ld, end %ld\n",
	(long int) storeCossFilenoToDiskOffset(sio->swap_filen, SD->fsdata),
	(long int) sio->st_size,
	(long int) (sio->swap_filen + sio->st_size));
    assert(-1 != sio->swap_filen);

    sio->callback = callback;
    sio->file_callback = file_callback;
    sio->callback_data = callback_data;
    cbdataLock(callback_data);
    sio->e = (StoreEntry *) e;

    cstate->flags.writing = 0;
    cstate->flags.reading = 0;
    cstate->readbuffer = NULL;
    cstate->reqdiskoffset = -1;

    /* Now add it into the index list */
    storeCossAdd(SD, e);

    storeCossMemBufLock(SD, sio);
    coss_stats.create.success++;
    return sio;
}

storeIOState *
storeCossOpen(SwapDir * SD, StoreEntry * e, STFNCB * file_callback,
    STIOCB * callback, void *callback_data)
{
    storeIOState *sio;
    char *p;
    CossState *cstate;
    sfileno f = e->swap_filen;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    debug(79, 3) ("storeCossOpen: offset %d\n", f);
    coss_stats.open.ops++;

    sio = cbdataAlloc(storeIOState);
    cstate = memPoolAlloc(coss_state_pool);

    sio->fsstate = cstate;
    sio->swap_filen = f;
    sio->swap_dirn = SD->index;
    sio->offset = 0;
    sio->mode = O_RDONLY | O_BINARY;
    sio->callback = callback;
    sio->file_callback = file_callback;
    sio->callback_data = callback_data;
    cbdataLock(callback_data);
    sio->st_size = e->swap_file_sz;
    sio->e = e;

    cstate->flags.writing = 0;
    cstate->flags.reading = 0;
    cstate->readbuffer = NULL;
    cstate->reqdiskoffset = -1;
    p = storeCossMemPointerFromDiskOffset(SD, storeCossFilenoToDiskOffset(f, cs), NULL);
    /* make local copy so we don't have to lock membuf */
    if (p) {
	cstate->readbuffer = xmalloc(sio->st_size);
	xmemcpy(cstate->readbuffer, p, sio->st_size);
	coss_stats.open_mem_hits++;
    } else {
	/* Do the allocation */
	/* this is the first time we've been called on a new sio
	 * read the whole object into memory, then return the 
	 * requested amount
	 */
	coss_stats.open_mem_misses++;
	/*
	 * This bit of code actually does the LRU disk thing - we realloc
	 * a place for the object here, and the file_read() reads the object
	 * into the cossmembuf for later writing ..
	 */
	cstate->reqdiskoffset = storeCossFilenoToDiskOffset(sio->swap_filen, cs);
	sio->swap_filen = storeCossAllocate(SD, e, COSS_ALLOC_REALLOC);
	if (sio->swap_filen == -1) {
	    /* We have to clean up neatly .. */
	    coss_stats.open.fail++;
	    cbdataFree(sio);
	    cs->numcollisions++;
	    debug(79, 2) ("storeCossOpen: Reallocation of %d/%d failed\n", e->swap_dirn, e->swap_filen);
	    /* XXX XXX XXX Will squid call storeUnlink for this object? */
	    return NULL;
	}
	/* Notify the upper levels that we've changed file number */
	sio->file_callback(sio->callback_data, 0, sio);

	/*
	 * lock the buffer so it doesn't get swapped out on us
	 * this will get unlocked in storeCossClose
	 */
	storeCossMemBufLock(SD, sio);

	/*
	 * Do the index magic to keep the disk and memory LRUs identical
	 */
	storeCossRemove(SD, e);
	storeCossAdd(SD, e);

	/*
	 * NOTE cstate->readbuffer is NULL.  We'll actually read
	 * the disk data into the MemBuf in storeCossRead() and
	 * return that pointer back to the caller
	 */
    }
    coss_stats.open.success++;
    return sio;
}

void
storeCossClose(SwapDir * SD, storeIOState * sio)
{
    debug(79, 3) ("storeCossClose: offset %d\n", sio->swap_filen);
    coss_stats.close.ops++;
    coss_stats.close.success++;
    storeCossMemBufUnlock(SD, sio);
    storeCossIOCallback(sio, 0);
}

void
storeCossRead(SwapDir * SD, storeIOState * sio, char *buf, size_t size, squid_off_t offset, STRCB * callback, void *callback_data)
{
    char *p;
    CossState *cstate = (CossState *) sio->fsstate;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    coss_stats.read.ops++;
    assert(sio->read.callback == NULL);
    assert(sio->read.callback_data == NULL);
    sio->read.callback = callback;
    sio->read.callback_data = callback_data;
    debug(79, 3) ("storeCossRead: offset %ld\n", (long int) offset);
    sio->offset = offset;
    cstate->flags.reading = 1;
    if ((offset + size) > sio->st_size)
	size = sio->st_size - offset;
    cstate->requestlen = size;
    cstate->requestbuf = buf;
    cstate->requestoffset = offset;
    if (cstate->readbuffer == NULL) {
	p = storeCossMemPointerFromDiskOffset(SD, storeCossFilenoToDiskOffset(sio->swap_filen, cs), NULL);
	a_file_read(&cs->aq, cs->fd,
	    p,
	    sio->st_size,
	    cstate->reqdiskoffset,
	    storeCossReadDone,
	    sio);
	cstate->reqdiskoffset = 0;	/* XXX */
    } else {
	/*
	 * It was copied from memory in storeCossOpen()
	 */
	storeCossReadDone(cs->fd,
	    cstate->readbuffer,
	    sio->st_size,
	    0,
	    sio);
    }
}

void
storeCossWrite(SwapDir * SD, storeIOState * sio, char *buf, size_t size, squid_off_t offset, FREE * free_func)
{
    char *dest;
    CossMemBuf *membuf;
    off_t diskoffset;

    /*
     * If we get handed an object with a size of -1,
     * the squid code is broken
     */
    assert(sio->e->mem_obj->object_sz != -1);
    coss_stats.write.ops++;

    debug(79, 3) ("storeCossWrite: offset %ld, len %lu\n", (long int) sio->offset, (unsigned long int) size);
    diskoffset = storeCossFilenoToDiskOffset(sio->swap_filen, SD->fsdata) + sio->offset;
    dest = storeCossMemPointerFromDiskOffset(SD, diskoffset, &membuf);
    assert(dest != NULL);
    xmemcpy(dest, buf, size);
    sio->offset += size;
    if (free_func)
	(free_func) (buf);
    coss_stats.write.success++;
}


/*  === STATIC =========================================================== */

static void
storeCossReadDone(int fd, const char *buf, int len, int errflag, void *my_data)
{
    storeIOState *sio = my_data;
    char *p;
    STRCB *callback = sio->read.callback;
    void *their_data = sio->read.callback_data;
    SwapDir *SD = INDEXSD(sio->swap_dirn);
    CossState *cstate = (CossState *) sio->fsstate;
    ssize_t rlen;

    debug(79, 3) ("storeCossReadDone: fileno %d, FD %d, len %d\n",
	sio->swap_filen, fd, len);
    cstate->flags.reading = 0;
    if (errflag) {
	coss_stats.read.fail++;
	if (errflag > 0) {
	    errno = errflag;
	    debug(79, 1) ("storeCossReadDone: error: %s\n", xstrerror());
	} else {
	    debug(79, 1) ("storeCossReadDone: got failure (%d)\n", errflag);
	}
	rlen = -1;
    } else {
	coss_stats.read.success++;
	if (cstate->readbuffer == NULL) {
	    cstate->readbuffer = xmalloc(sio->st_size);
	    p = storeCossMemPointerFromDiskOffset(SD,
		storeCossFilenoToDiskOffset(sio->swap_filen, SD->fsdata),
		NULL);
	    xmemcpy(cstate->readbuffer, p, sio->st_size);
	}
	sio->offset += len;
	xmemcpy(cstate->requestbuf, &cstate->readbuffer[cstate->requestoffset],
	    cstate->requestlen);
	rlen = (size_t) cstate->requestlen;
    }
    assert(callback);
    assert(their_data);
    sio->read.callback = NULL;
    sio->read.callback_data = NULL;
    if (cbdataValid(their_data))
	callback(their_data, cstate->requestbuf, rlen);
}

static void
storeCossIOCallback(storeIOState * sio, int errflag)
{
    CossState *cstate = (CossState *) sio->fsstate;
    debug(79, 3) ("storeCossIOCallback: errflag=%d\n", errflag);
    assert(NULL == cstate->locked_membuf);
    xfree(cstate->readbuffer);
    if (cbdataValid(sio->callback_data))
	sio->callback(sio->callback_data, errflag, sio);
    cbdataUnlock(sio->callback_data);
    sio->callback_data = NULL;
    cbdataFree(sio);
}

static char *
storeCossMemPointerFromDiskOffset(SwapDir * SD, size_t offset, CossMemBuf ** mb)
{
    CossMemBuf *t;
    dlink_node *m;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    for (m = cs->membufs.head; m; m = m->next) {
	t = m->data;
	if ((offset >= t->diskstart) && (offset < t->diskend)) {
	    if (mb)
		*mb = t;
	    return &t->buffer[offset - t->diskstart];
	}
    }

    if (mb)
	*mb = NULL;
    return NULL;
}

static CossMemBuf *
storeCossFilenoToMembuf(SwapDir * SD, sfileno s)
{
    CossMemBuf *t = NULL;
    dlink_node *m;
    CossInfo *cs = (CossInfo *) SD->fsdata;
    off_t o = storeCossFilenoToDiskOffset(s, cs);
    for (m = cs->membufs.head; m; m = m->next) {
	t = m->data;
	if ((o >= t->diskstart) && (o < t->diskend))
	    break;
    }
    assert(t);
    return t;
}

static void
storeCossMemBufLock(SwapDir * SD, storeIOState * sio)
{
    CossMemBuf *t = storeCossFilenoToMembuf(SD, sio->swap_filen);
    CossState *cstate = (CossState *) sio->fsstate;
    debug(79, 3) ("storeCossMemBufLock: locking %p, lockcount %d\n",
	t, t->lockcount);
    cstate->locked_membuf = t;
    t->lockcount++;
}

static void
storeCossMemBufUnlock(SwapDir * SD, storeIOState * sio)
{
    CossState *cstate = (CossState *) sio->fsstate;
    CossMemBuf *t = cstate->locked_membuf;
    if (NULL == t)
	return;
    debug(79, 3) ("storeCossMemBufUnlock: unlocking %p, lockcount %d\n",
	t, t->lockcount);
    t->lockcount--;
    cstate->locked_membuf = NULL;
    storeCossMaybeWriteMemBuf(SD, t);
}

static void
storeCossMaybeWriteMemBuf(SwapDir * SD, CossMemBuf * t)
{
    membuf_describe(t, 3, __LINE__);
    if (!t->flags.full)
	debug(79, 3) ("membuf %p not full\n", t);
    else if (t->flags.writing)
	debug(79, 3) ("membuf %p writing\n", t);
    else if (t->lockcount)
	debug(79, 3) ("membuf %p lockcount=%d\n", t, t->lockcount);
    else
	storeCossWriteMemBuf(SD, t);
}

void
storeCossSync(SwapDir * SD)
{
    CossInfo *cs = (CossInfo *) SD->fsdata;
    dlink_node *m;
    int end;

    /* First, flush pending IO ops */
    a_file_syncqueue(&cs->aq);

    /* Then, flush any in-memory partial membufs */
    if (!cs->membufs.head)
	return;
    for (m = cs->membufs.head; m; m = m->next) {
	CossMemBuf *t = m->data;
	if (t->flags.writing) {
	    debug(79, 1) ("WARNING: sleeping for 5 seconds in storeCossSync()\n");
	    sleep(5);		/* XXX EEEWWW! */
	}
	lseek(cs->fd, t->diskstart, SEEK_SET);
	end = (t == cs->current_membuf) ? cs->current_offset : t->diskend;
	FD_WRITE_METHOD(cs->fd, t->buffer, end - t->diskstart);
    }
}

static void
storeCossWriteMemBuf(SwapDir * SD, CossMemBuf * t)
{
    CossInfo *cs = (CossInfo *) SD->fsdata;
    coss_stats.stripe_write.ops++;
    debug(79, 3) ("storeCossWriteMemBuf: offset %ld, len %ld\n",
	(long int) t->diskstart, (long int) (t->diskend - t->diskstart));
    t->flags.writing = 1;
    a_file_write(&cs->aq, cs->fd, t->diskstart, &t->buffer,
	t->diskend - t->diskstart, storeCossWriteMemBufDone, t, NULL);
}


static void
storeCossWriteMemBufDone(int fd, int errflag, size_t len, void *my_data)
{
    CossMemBuf *t = my_data;
    CossInfo *cs = (CossInfo *) t->SD->fsdata;

    debug(79, 3) ("storeCossWriteMemBufDone: buf %p, len %ld\n", t, (long int) len);
    if (errflag) {
	coss_stats.stripe_write.fail++;
	debug(79, 1) ("storeCossWriteMemBufDone: got failure (%d)\n", errflag);
	debug(79, 1) ("FD %d, size=%x\n", fd, (int) (t->diskend - t->diskstart));
    } else {
	coss_stats.stripe_write.success++;
    }

    dlinkDelete(&t->node, &cs->membufs);
    cbdataFree(t);
    coss_stats.stripes--;
}

static CossMemBuf *
storeCossCreateMemBuf(SwapDir * SD, size_t start,
    sfileno curfn, int *collision)
{
    CossMemBuf *newmb, *t;
    StoreEntry *e;
    dlink_node *m, *prev;
    int numreleased = 0;
    CossInfo *cs = (CossInfo *) SD->fsdata;

    newmb = cbdataAlloc(CossMemBuf);
    newmb->diskstart = start;
    debug(79, 3) ("storeCossCreateMemBuf: creating new membuf at %ld\n", (long int) newmb->diskstart);
    debug(79, 3) ("storeCossCreateMemBuf: at %p\n", newmb);
    newmb->diskend = newmb->diskstart + COSS_MEMBUF_SZ;
    newmb->flags.full = 0;
    newmb->flags.writing = 0;
    newmb->lockcount = 0;
    newmb->SD = SD;
    /* XXX This should be reversed, with the new buffer last in the chain */
    dlinkAdd(newmb, &newmb->node, &cs->membufs);

    /* Print out the list of membufs */
    debug(79, 3) ("storeCossCreateMemBuf: membuflist:\n");
    for (m = cs->membufs.head; m; m = m->next) {
	t = m->data;
	membuf_describe(t, 3, __LINE__);
    }

    /*
     * Kill objects from the tail to make space for a new chunk
     */
    for (m = cs->index.tail; m; m = prev) {
	off_t o;
	prev = m->prev;
	e = m->data;
	o = storeCossFilenoToDiskOffset(e->swap_filen, cs);
	if (curfn == e->swap_filen)
	    *collision = 1;	/* Mark an object alloc collision */
	if ((o >= newmb->diskstart) && (o < newmb->diskend)) {
	    storeRelease(e);
	    numreleased++;
	} else
	    break;
    }
    if (numreleased > 0)
	debug(79, 3) ("storeCossCreateMemBuf: this allocation released %d storeEntries\n", numreleased);
    coss_stats.stripes++;
    return newmb;
}

/*
 * Creates the initial membuf after rebuild
 */
void
storeCossStartMembuf(SwapDir * sd)
{
    CossInfo *cs = (CossInfo *) sd->fsdata;
    CossMemBuf *newmb;
    CBDATA_INIT_TYPE_FREECB(storeIOState, storeCossIOFreeEntry);
    CBDATA_INIT_TYPE_FREECB(CossMemBuf, NULL);
    CBDATA_INIT_TYPE_FREECB(storeIOState, storeCossIOFreeEntry);
    newmb = storeCossCreateMemBuf(sd, cs->current_offset, -1, NULL);
    assert(!cs->current_membuf);
    cs->current_membuf = newmb;
}

/*
 * Clean up any references from the SIO before it get's released.
 */
static void
storeCossIOFreeEntry(void *sio)
{
    memPoolFree(coss_state_pool, ((storeIOState *) sio)->fsstate);
}

static off_t
storeCossFilenoToDiskOffset(sfileno f, CossInfo * cs)
{
    return (off_t) f << cs->blksz_bits;
}

static sfileno
storeCossDiskOffsetToFileno(off_t o, CossInfo * cs)
{
    assert(0 == (o & cs->blksz_mask));
    return o >> cs->blksz_bits;
}

static void
membuf_describe(CossMemBuf * t, int level, int line)
{
    debug(79, level) ("membuf %p, LC:%02d, ST:%010lu, FL:%c%c\n",
	t,
	t->lockcount,
	(unsigned long) t->diskstart,
	t->flags.full ? 'F' : '.',
	t->flags.writing ? 'W' : '.');
}
