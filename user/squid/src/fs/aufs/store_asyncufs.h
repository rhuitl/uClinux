/*
 * store_aufs.h
 *
 * Internal declarations for the aufs routines
 */

#ifndef __STORE_ASYNCUFS_H__
#define __STORE_ASYNCUFS_H__

extern int n_asyncufs_dirs;
extern int squidaio_nthreads;
extern int squidaio_magic1;
extern int squidaio_magic2;

/* Base number of threads if not specified to configure.
 * Weighted by number of directories (see aiops.c) */
#define THREAD_FACTOR 16

/* Queue limit where swapouts are deferred (load calculation) */
#define MAGIC1_FACTOR 10
#define MAGIC1 squidaio_magic1
/* Queue limit where swapins are deferred (open/create fails) */
#define MAGIC2_FACTOR 20
#define MAGIC2 squidaio_magic2

/* Which operations to run async */
#define ASYNC_OPEN 1
#define ASYNC_CLOSE 0
#define ASYNC_CREATE 1
#define ASYNC_WRITE 0
#define ASYNC_READ 1

struct _squidaio_result_t {
    int aio_return;
    int aio_errno;
    void *_data;		/* Internal housekeeping */
    void *data;			/* Available to the caller */
};

typedef struct _squidaio_result_t squidaio_result_t;

typedef void AIOCB(int fd, void *cbdata, const char *buf, int aio_return, int aio_errno);

void squidaio_init(void);
void squidaio_shutdown(void);
int squidaio_cancel(squidaio_result_t *);
int squidaio_open(const char *, int, mode_t, squidaio_result_t *);
int squidaio_read(int, char *, int, off_t, int, squidaio_result_t *);
int squidaio_write(int, char *, int, off_t, int, squidaio_result_t *);
int squidaio_close(int, squidaio_result_t *);
int squidaio_stat(const char *, struct stat *, squidaio_result_t *);
int squidaio_unlink(const char *, squidaio_result_t *);
int squidaio_truncate(const char *, off_t length, squidaio_result_t *);
int squidaio_opendir(const char *, squidaio_result_t *);
squidaio_result_t *squidaio_poll_done(void);
int squidaio_operations_pending(void);
int squidaio_sync(void);
int squidaio_get_queue_len(void);
void *squidaio_xmalloc(int size);
void squidaio_xfree(void *p, int size);
void squidaio_stats(StoreEntry *);

void aioInit(void);
void aioDone(void);
void aioCancel(int);
void aioOpen(const char *, int, mode_t, AIOCB *, void *);
void aioClose(int);
void aioWrite(int, off_t offset, char *, int size, AIOCB *, void *, FREE *);
void aioRead(int, off_t offset, int size, AIOCB *, void *);
void aioStat(char *, struct stat *, AIOCB *, void *);
void aioUnlink(const char *, AIOCB *, void *);
void aioTruncate(const char *, off_t length, AIOCB *, void *);
int aioCheckCallbacks(SwapDir *);
void aioSync(SwapDir *);
int aioQueueSize(void);

struct _squidaioinfo_t {
    int swaplog_fd;
    int l1;
    int l2;
    fileMap *map;
    int suggest;
};

struct _squidaiostate_t {
    int fd;
    struct {
	unsigned int close_request:1;
	unsigned int reading:1;
	unsigned int writing:1;
	unsigned int opening:1;
#if !ASYNC_WRITE
	unsigned int write_kicking:1;
#endif
	unsigned int inreaddone:1;
    } flags;
    char *read_buf;
    link_list *pending_writes;
    link_list *pending_reads;
};

struct _queued_write {
    char *buf;
    size_t size;
    off_t offset;
    FREE *free_func;
};

struct _queued_read {
    char *buf;
    size_t size;
    off_t offset;
    STRCB *callback;
    void *callback_data;
};

typedef struct _squidaioinfo_t squidaioinfo_t;
typedef struct _squidaiostate_t squidaiostate_t;

/* The squidaio_state memory pools */
extern MemPool *squidaio_state_pool;
extern MemPool *aufs_qread_pool;
extern MemPool *aufs_qwrite_pool;

extern void storeAufsDirMapBitReset(SwapDir *, sfileno);
extern int storeAufsDirMapBitAllocate(SwapDir *);

extern char *storeAufsDirFullPath(SwapDir * SD, sfileno filn, char *fullpath);
extern void storeAufsDirUnlinkFile(SwapDir *, sfileno);
extern void storeAufsDirReplAdd(SwapDir * SD, StoreEntry *);
extern void storeAufsDirReplRemove(StoreEntry *);

/*
 * Store IO stuff
 */
extern STOBJCREATE storeAufsCreate;
extern STOBJOPEN storeAufsOpen;
extern STOBJCLOSE storeAufsClose;
extern STOBJREAD storeAufsRead;
extern STOBJWRITE storeAufsWrite;
extern STOBJUNLINK storeAufsUnlink;

#endif
