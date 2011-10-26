#ifndef __COSS_H__
#define __COSS_H__

#ifndef COSS_MEMBUF_SZ
#define	COSS_MEMBUF_SZ	1048576
#endif

/* Note that swap_filen in sio/e are actually disk offsets too! */

/* What we're doing in storeCossAllocate() */
#define COSS_ALLOC_NOTIFY		0
#define COSS_ALLOC_ALLOCATE		1
#define COSS_ALLOC_REALLOC		2

struct _coss_stats {
    int stripes;
    struct {
	int alloc;
	int realloc;
	int collisions;
    } alloc;
    int disk_overflows;
    int stripe_overflows;
    int open_mem_hits;
    int open_mem_misses;
    struct {
	int ops;
	int success;
	int fail;
    } open, create, close, unlink, read, write, stripe_write;
};


struct _cossmembuf {
    dlink_node node;
    size_t diskstart;		/* in bytes */
    size_t diskend;		/* in bytes */
    SwapDir *SD;
    int lockcount;
    char buffer[COSS_MEMBUF_SZ];
    struct _cossmembuf_flags {
	unsigned int full:1;
	unsigned int writing:1;
    } flags;
};


/* Per-storedir info */
struct _cossinfo {
    dlink_list membufs;
    struct _cossmembuf *current_membuf;
    size_t current_offset;	/* in bytes */
    int fd;
    int swaplog_fd;
    int numcollisions;
    dlink_list index;
    int count;
    async_queue_t aq;
    dlink_node *walk_current;
    unsigned int blksz_bits;
    unsigned int blksz_mask;	/* just 1<<blksz_bits - 1 */
};

struct _cossindex {
    /* Note: the dlink_node MUST be the first member of the structure.
     * This member is later pointer typecasted to coss_index_node *.
     */
    dlink_node node;
};


/* Per-storeiostate info */
struct _cossstate {
    char *readbuffer;
    char *requestbuf;
    size_t requestlen;
    size_t requestoffset;	/* in blocks */
    sfileno reqdiskoffset;	/* in blocks */
    struct {
	unsigned int reading:1;
	unsigned int writing:1;
    } flags;
    struct _cossmembuf *locked_membuf;
};

typedef struct _cossmembuf CossMemBuf;
typedef struct _cossinfo CossInfo;
typedef struct _cossstate CossState;
typedef struct _cossindex CossIndexNode;

/* Whether the coss system has been setup or not */
extern int coss_initialised;
extern MemPool *coss_membuf_pool;
extern MemPool *coss_state_pool;
extern MemPool *coss_index_pool;

/*
 * Store IO stuff
 */
extern STOBJCREATE storeCossCreate;
extern STOBJOPEN storeCossOpen;
extern STOBJCLOSE storeCossClose;
extern STOBJREAD storeCossRead;
extern STOBJWRITE storeCossWrite;
extern STOBJUNLINK storeCossUnlink;
extern STSYNC storeCossSync;

extern void storeCossAdd(SwapDir *, StoreEntry *);
extern void storeCossRemove(SwapDir *, StoreEntry *);
extern void storeCossStartMembuf(SwapDir * SD);

extern struct _coss_stats coss_stats;

#endif
