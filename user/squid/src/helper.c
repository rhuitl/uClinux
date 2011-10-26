
/*
 * $Id: helper.c,v 1.34.2.18 2005/03/26 02:50:53 hno Exp $
 *
 * DEBUG: section 84    Helper process maintenance
 * AUTHOR: Harvest Derived?
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

#define HELPER_MAX_ARGS 64

static PF helperHandleRead;
static PF helperStatefulHandleRead;
static PF helperServerFree;
static PF helperStatefulServerFree;
static void Enqueue(helper * hlp, helper_request *);
static helper_request *Dequeue(helper * hlp);
static helper_stateful_request *StatefulDequeue(statefulhelper * hlp);
static helper_server *GetFirstAvailable(helper * hlp);
static helper_stateful_server *StatefulGetFirstAvailable(statefulhelper * hlp);
static void helperDispatch(helper_server * srv, helper_request * r);
static void helperStatefulDispatch(helper_stateful_server * srv, helper_stateful_request * r);
static void helperKickQueue(helper * hlp);
static void helperStatefulKickQueue(statefulhelper * hlp);
static void helperRequestFree(helper_request * r);
static void helperStatefulRequestFree(helper_stateful_request * r);
static void StatefulEnqueue(statefulhelper * hlp, helper_stateful_request * r);

void
helperOpenServers(helper * hlp)
{
    char *s;
    char *progname;
    char *shortname;
    char *procname;
    const char *args[HELPER_MAX_ARGS];
    char fd_note_buf[FD_DESC_SZ];
    helper_server *srv;
    int nargs = 0;
    int k;
    int x;
    int rfd;
    int wfd;
    wordlist *w;
    if (hlp->cmdline == NULL)
	return;
    progname = hlp->cmdline->key;
    if ((s = strrchr(progname, '/')))
	shortname = xstrdup(s + 1);
    else
	shortname = xstrdup(progname);
    debug(84, 1) ("helperOpenServers: Starting %d '%s' processes\n",
	hlp->n_to_start, shortname);
    procname = xmalloc(strlen(shortname) + 3);
    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);
    args[nargs++] = procname;
    for (w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next)
	args[nargs++] = w->key;
    args[nargs++] = NULL;
    assert(nargs <= HELPER_MAX_ARGS);
    for (k = 0; k < hlp->n_to_start; k++) {
	getCurrentTime();
	rfd = wfd = -1;
	x = ipcCreate(hlp->ipc_type,
	    progname,
	    args,
	    shortname,
	    &rfd,
	    &wfd);
	if (x < 0) {
	    debug(84, 1) ("WARNING: Cannot run '%s' process.\n", progname);
	    continue;
	}
	hlp->n_running++;
	hlp->n_active++;
	srv = cbdataAlloc(helper_server);
	srv->pid = x;
	srv->index = k;
	srv->rfd = rfd;
	srv->wfd = wfd;
	srv->buf = memAllocate(MEM_8K_BUF);
	srv->buf_sz = 8192;
	srv->offset = 0;
	srv->parent = hlp;
	cbdataLock(hlp);	/* lock because of the parent backlink */
	dlinkAddTail(srv, &srv->link, &hlp->servers);
	if (rfd == wfd) {
	    snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	} else {
	    snprintf(fd_note_buf, FD_DESC_SZ, "reading %s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	    snprintf(fd_note_buf, FD_DESC_SZ, "writing %s #%d", shortname, k + 1);
	    fd_note(wfd, fd_note_buf);
	}
	commSetNonBlocking(rfd);
	if (wfd != rfd)
	    commSetNonBlocking(wfd);
	comm_add_close_handler(rfd, helperServerFree, srv);
	commSetSelect(srv->rfd, COMM_SELECT_READ, helperHandleRead, srv, 0);
    }
    hlp->last_restart = squid_curtime;
    safe_free(shortname);
    safe_free(procname);
    helperKickQueue(hlp);
}

void
helperStatefulOpenServers(statefulhelper * hlp)
{
    char *s;
    char *progname;
    char *shortname;
    char *procname;
    const char *args[HELPER_MAX_ARGS];
    char fd_note_buf[FD_DESC_SZ];
    helper_stateful_server *srv;
    int nargs = 0;
    int k;
    int x;
    int rfd;
    int wfd;
    wordlist *w;
    if (hlp->cmdline == NULL)
	return;
    progname = hlp->cmdline->key;
    if ((s = strrchr(progname, '/')))
	shortname = xstrdup(s + 1);
    else
	shortname = xstrdup(progname);
    debug(84, 1) ("helperStatefulOpenServers: Starting %d '%s' processes\n",
	hlp->n_to_start, shortname);
    procname = xmalloc(strlen(shortname) + 3);
    snprintf(procname, strlen(shortname) + 3, "(%s)", shortname);
    args[nargs++] = procname;
    for (w = hlp->cmdline->next; w && nargs < HELPER_MAX_ARGS; w = w->next)
	args[nargs++] = w->key;
    args[nargs++] = NULL;
    assert(nargs <= HELPER_MAX_ARGS);
    for (k = 0; k < hlp->n_to_start; k++) {
	getCurrentTime();
	rfd = wfd = -1;
	x = ipcCreate(hlp->ipc_type,
	    progname,
	    args,
	    shortname,
	    &rfd,
	    &wfd);
	if (x < 0) {
	    debug(84, 1) ("WARNING: Cannot run '%s' process.\n", progname);
	    continue;
	}
	hlp->n_running++;
	hlp->n_active++;
	srv = cbdataAlloc(helper_stateful_server);
	srv->pid = x;
	srv->flags.reserved = 0;
	srv->stats.submits = 0;
	srv->index = k;
	srv->rfd = rfd;
	srv->wfd = wfd;
	srv->buf = memAllocate(MEM_8K_BUF);
	srv->buf_sz = 8192;
	srv->offset = 0;
	srv->parent = hlp;
	if (hlp->datapool != NULL)
	    srv->data = memPoolAlloc(hlp->datapool);
	cbdataLock(hlp);	/* lock because of the parent backlink */
	dlinkAddTail(srv, &srv->link, &hlp->servers);
	if (rfd == wfd) {
	    snprintf(fd_note_buf, FD_DESC_SZ, "%s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	} else {
	    snprintf(fd_note_buf, FD_DESC_SZ, "reading %s #%d", shortname, k + 1);
	    fd_note(rfd, fd_note_buf);
	    snprintf(fd_note_buf, FD_DESC_SZ, "writing %s #%d", shortname, k + 1);
	    fd_note(wfd, fd_note_buf);
	}
	commSetNonBlocking(rfd);
	if (wfd != rfd)
	    commSetNonBlocking(wfd);
	comm_add_close_handler(rfd, helperStatefulServerFree, srv);
	commSetSelect(srv->rfd, COMM_SELECT_READ, helperStatefulHandleRead, srv, 0);
    }
    hlp->last_restart = squid_curtime;
    safe_free(shortname);
    safe_free(procname);
    helperStatefulKickQueue(hlp);
}


void
helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data)
{
    helper_request *r = memAllocate(MEM_HELPER_REQUEST);
    helper_server *srv;
    if (hlp == NULL) {
	debug(84, 3) ("helperSubmit: hlp == NULL\n");
	callback(data, NULL);
	return;
    }
    r->callback = callback;
    r->data = data;
    r->buf = xstrdup(buf);
    cbdataLock(r->data);
    if ((srv = GetFirstAvailable(hlp)))
	helperDispatch(srv, r);
    else
	Enqueue(hlp, r);
    debug(84, 9) ("helperSubmit: %s\n", buf);
}

void
helperStatefulSubmit(statefulhelper * hlp, const char *buf, HLPSCB * callback, void *data, helper_stateful_server * srv)
{
    helper_stateful_request *r = memAllocate(MEM_HELPER_STATEFUL_REQUEST);
    if (hlp == NULL) {
	debug(84, 3) ("helperStatefulSubmit: hlp == NULL\n");
	callback(data, 0, NULL);
	return;
    }
    r->callback = callback;
    r->data = data;
    if (buf)
	r->buf = xstrdup(buf);
    cbdataLock(r->data);
    if (!srv)
	srv = helperStatefulGetServer(hlp);
    if (srv) {
	debug(84, 5) ("helperStatefulSubmit: sever %p, buf '%s'.\n", srv, buf ? buf : "NULL");
	assert(!srv->request);
	assert(!srv->flags.busy);
	helperStatefulDispatch(srv, r);
    } else {
	debug(84, 9) ("helperStatefulSubmit: enqueued, buf '%s'.\n", buf ? buf : "NULL");
	StatefulEnqueue(hlp, r);
    }
}

helper_stateful_server *
helperStatefulGetServer(statefulhelper * hlp)
/* find a server for this request */
{
    helper_stateful_server *srv = NULL;
    if (hlp == NULL) {
	debug(84, 3) ("helperStatefulGetServer: hlp == NULL\n");
	return NULL;
    }
    debug(84, 5) ("helperStatefulGetServer: Running servers %d.\n", hlp->n_running);
    if (hlp->n_running == 0) {
	debug(84, 1) ("helperStatefulGetServer: No running servers!. \n");
	return NULL;
    }
    srv = StatefulGetFirstAvailable(hlp);
    if (srv)
	srv->flags.reserved = 1;
    debug(84, 5) ("helperStatefulGetServer: Returning %p\n", srv);
    return srv;
}

/* puts this helper forcibly back in the queue. */
void
helperStatefulReset(helper_stateful_server * srv)
{
    statefulhelper *hlp = srv->parent;
    helper_stateful_request *r;
    debug(84, 5) ("helperStatefulReset: %p\n", srv);
    r = srv->request;
    if (r != NULL) {
	/* reset attempt DURING an outstaning request */
	debug(84, 1) ("helperStatefulReset: RESET During request %s \n",
	    hlp->id_name);
	srv->flags.busy = 0;
	srv->offset = 0;
	helperStatefulRequestFree(r);
	srv->request = NULL;
    }
    srv->flags.busy = 0;
    srv->flags.reserved = 0;
    if ((srv->parent->Reset != NULL) && (srv->data))
	srv->parent->Reset(srv->data);
    if (srv->flags.shutdown) {
	int wfd = srv->wfd;
	srv->wfd = -1;
	comm_close(wfd);
    } else {
	helperStatefulKickQueue(hlp);
    }
}

/* puts this helper back in the queue. */
void
helperStatefulReleaseServer(helper_stateful_server * srv)
{
    debug(84, 5) ("helperStatefulReleaseServer: %p\n", srv);
    assert(!srv->request);
    assert(srv->flags.reserved);
    helperStatefulReset(srv);
}

void *
helperStatefulServerGetData(helper_stateful_server * srv)
/* return a pointer to the stateful routines data area */
{
    return srv->data;
}

void
helperStats(StoreEntry * sentry, helper * hlp)
{
    helper_server *srv;
    dlink_node *link;
    double tt;
    storeAppendPrintf(sentry, "program: %s\n",
	hlp->cmdline->key);
    storeAppendPrintf(sentry, "number running: %d of %d\n",
	hlp->n_running, hlp->n_to_start);
    storeAppendPrintf(sentry, "requests sent: %d\n",
	hlp->stats.requests);
    storeAppendPrintf(sentry, "replies received: %d\n",
	hlp->stats.replies);
    storeAppendPrintf(sentry, "queue length: %d\n",
	hlp->stats.queue_size);
    storeAppendPrintf(sentry, "avg service time: %.2f msec\n",
	(double) hlp->stats.avg_svc_time / 1000.0);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "%7s\t%7s\t%7s\t%11s\t%s\t%7s\t%7s\t%7s\n",
	"#",
	"FD",
	"PID",
	"# Requests",
	"Flags",
	"Time",
	"Offset",
	"Request");
    for (link = hlp->servers.head; link; link = link->next) {
	srv = link->data;
	tt = 0.001 * tvSubMsec(srv->dispatch_time,
	    srv->flags.busy ? current_time : srv->answer_time);
	storeAppendPrintf(sentry, "%7d\t%7d\t%7d\t%11d\t%c%c%c\t%7.3f\t%7d\t%s\n",
	    srv->index + 1,
	    srv->rfd,
	    srv->pid,
	    srv->stats.uses,
	    srv->flags.busy ? 'B' : ' ',
	    srv->flags.closing ? 'C' : ' ',
	    srv->flags.shutdown ? 'S' : ' ',
	    tt < 0.0 ? 0.0 : tt,
	    srv->offset,
	    srv->request ? log_quote(srv->request->buf) : "(none)");
    }
    storeAppendPrintf(sentry, "\nFlags key:\n\n");
    storeAppendPrintf(sentry, "   A = ALIVE\n");
    storeAppendPrintf(sentry, "   B = BUSY\n");
    storeAppendPrintf(sentry, "   C = CLOSING\n");
    storeAppendPrintf(sentry, "   S = SHUTDOWN\n");
}

void
helperStatefulStats(StoreEntry * sentry, statefulhelper * hlp)
{
    helper_stateful_server *srv;
    dlink_node *link;
    double tt;
    storeAppendPrintf(sentry, "number running: %d of %d\n",
	hlp->n_running, hlp->n_to_start);
    storeAppendPrintf(sentry, "requests sent: %d\n",
	hlp->stats.requests);
    storeAppendPrintf(sentry, "replies received: %d\n",
	hlp->stats.replies);
    storeAppendPrintf(sentry, "queue length: %d\n",
	hlp->stats.queue_size);
    storeAppendPrintf(sentry, "avg service time: %d msec\n",
	hlp->stats.avg_svc_time);
    storeAppendPrintf(sentry, "\n");
    storeAppendPrintf(sentry, "%7s\t%7s\t%7s\t%11s\t%s\t%7s\t%7s\t%7s\n",
	"#",
	"FD",
	"PID",
	"# Requests",
	"Flags",
	"Time",
	"Offset",
	"Request");
    for (link = hlp->servers.head; link; link = link->next) {
	srv = link->data;
	tt = 0.001 * tvSubMsec(srv->dispatch_time, current_time);
	storeAppendPrintf(sentry, "%7d\t%7d\t%7d\t%11d\t%c%c%c%c\t%7.3f\t%7d\t%s\n",
	    srv->index + 1,
	    srv->rfd,
	    srv->pid,
	    srv->stats.uses,
	    srv->flags.busy ? 'B' : ' ',
	    srv->flags.closing ? 'C' : ' ',
	    srv->flags.reserved ? 'R' : ' ',
	    srv->flags.shutdown ? 'S' : ' ',
	    tt < 0.0 ? 0.0 : tt,
	    srv->offset,
	    srv->request ? log_quote(srv->request->buf) : "(none)");
    }
    storeAppendPrintf(sentry, "\nFlags key:\n\n");
    storeAppendPrintf(sentry, "   A = ALIVE\n");
    storeAppendPrintf(sentry, "   B = BUSY\n");
    storeAppendPrintf(sentry, "   C = CLOSING\n");
    storeAppendPrintf(sentry, "   R = RESERVED or DEFERRED\n");
    storeAppendPrintf(sentry, "   S = SHUTDOWN\n");
    storeAppendPrintf(sentry, "   P = PLACEHOLDER\n");
}

void
helperShutdown(helper * hlp)
{
    dlink_node *link = hlp->servers.head;
    while (link) {
	int wfd;
	helper_server *srv;
	srv = link->data;
	link = link->next;
	if (srv->flags.shutdown) {
	    debug(84, 3) ("helperShutdown: %s #%d is already shut down\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	hlp->n_active--;
	assert(hlp->n_active >= 0);
	srv->flags.shutdown = 1;	/* request it to shut itself down */
	if (srv->flags.closing) {
	    debug(84, 3) ("helperShutdown: %s #%d is CLOSING.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	if (srv->flags.busy) {
	    debug(84, 3) ("helperShutdown: %s #%d is BUSY.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	srv->flags.closing = 1;
	wfd = srv->wfd;
	srv->wfd = -1;
	comm_close(wfd);
    }
}

void
helperStatefulShutdown(statefulhelper * hlp)
{
    dlink_node *link = hlp->servers.head;
    helper_stateful_server *srv;
    int wfd;
    while (link) {
	srv = link->data;
	link = link->next;
	if (srv->flags.shutdown) {
	    debug(84, 3) ("helperStatefulShutdown: %s #%d is already shut down.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	hlp->n_active--;
	assert(hlp->n_active >= 0);
	srv->flags.shutdown = 1;	/* request it to shut itself down */
	if (srv->flags.busy) {
	    debug(84, 3) ("helperStatefulShutdown: %s #%d is BUSY.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	if (srv->flags.closing) {
	    debug(84, 3) ("helperStatefulShutdown: %s #%d is CLOSING.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	if (srv->flags.reserved) {
	    debug(84, 3) ("helperStatefulShutdown: %s #%d is RESERVED.\n",
		hlp->id_name, srv->index + 1);
	    continue;
	}
	srv->flags.closing = 1;
	wfd = srv->wfd;
	srv->wfd = -1;
	comm_close(wfd);
    }
}


helper *
helperCreate(const char *name)
{
    helper *hlp;
    hlp = cbdataAlloc(helper);
    hlp->id_name = name;
    return hlp;
}

statefulhelper *
helperStatefulCreate(const char *name)
{
    statefulhelper *hlp;
    hlp = cbdataAlloc(statefulhelper);
    hlp->id_name = name;
    return hlp;
}


void
helperFree(helper * hlp)
{
    if (!hlp)
	return;
    /* note, don't free hlp->name, it probably points to static memory */
    if (hlp->queue.head)
	debug(84, 0) ("WARNING: freeing %s helper with %d requests queued\n",
	    hlp->id_name, hlp->stats.queue_size);
    cbdataFree(hlp);
}

void
helperStatefulFree(statefulhelper * hlp)
{
    if (!hlp)
	return;
    /* note, don't free hlp->name, it probably points to static memory */
    if (hlp->queue.head)
	debug(84, 0) ("WARNING: freeing %s helper with %d requests queued\n",
	    hlp->id_name, hlp->stats.queue_size);
    cbdataFree(hlp);
}


/* ====================================================================== */
/* LOCAL FUNCTIONS */
/* ====================================================================== */

static void
helperServerFree(int fd, void *data)
{
    helper_server *srv = data;
    helper *hlp = srv->parent;
    helper_request *r;
    assert(srv->rfd == fd);
    if (srv->buf) {
	memFree(srv->buf, MEM_8K_BUF);
	srv->buf = NULL;
    }
    if ((r = srv->request)) {
	if (cbdataValid(r->data))
	    r->callback(r->data, srv->buf);
	helperRequestFree(r);
	srv->request = NULL;
    }
    if (srv->wfd != srv->rfd && srv->wfd != -1)
	comm_close(srv->wfd);
    dlinkDelete(&srv->link, &hlp->servers);
    hlp->n_running--;
    assert(hlp->n_running >= 0);
    if (!srv->flags.shutdown) {
	hlp->n_active--;
	assert(hlp->n_active >= 0);
	debug(84, 0) ("WARNING: %s #%d (FD %d) exited\n",
	    hlp->id_name, srv->index + 1, fd);
	if (hlp->n_active <= hlp->n_to_start / 2) {
	    debug(80, 0) ("Too few %s processes are running\n", hlp->id_name);
	    if (hlp->last_restart > squid_curtime - 30)
		fatalf("The %s helpers are crashing too rapidly, need help!\n", hlp->id_name);
	    debug(80, 0) ("Starting new helpers\n");
	    helperOpenServers(hlp);
	}
    }
    cbdataUnlock(srv->parent);
    cbdataFree(srv);
}

static void
helperStatefulServerFree(int fd, void *data)
{
    helper_stateful_server *srv = data;
    statefulhelper *hlp = srv->parent;
    helper_stateful_request *r;
    assert(srv->rfd == fd);
    if (srv->buf) {
	memFree(srv->buf, MEM_8K_BUF);
	srv->buf = NULL;
    }
    if ((r = srv->request)) {
	if (cbdataValid(r->data))
	    r->callback(r->data, srv, srv->buf);
	helperStatefulRequestFree(r);
	srv->request = NULL;
    }
    /* TODO: walk the local queue of requests and carry them all out */
    if (srv->wfd != srv->rfd && srv->wfd != -1)
	comm_close(srv->wfd);
    dlinkDelete(&srv->link, &hlp->servers);
    hlp->n_running--;
    assert(hlp->n_running >= 0);
    if (!srv->flags.shutdown) {
	hlp->n_active--;
	assert(hlp->n_active >= 0);
	debug(84, 0) ("WARNING: %s #%d (FD %d) exited\n",
	    hlp->id_name, srv->index + 1, fd);
	if (hlp->n_active <= hlp->n_to_start / 2) {
	    debug(80, 0) ("Too few %s processes are running\n", hlp->id_name);
	    if (hlp->last_restart > squid_curtime - 30)
		fatalf("The %s helpers are crashing too rapidly, need help!\n", hlp->id_name);
	    debug(80, 0) ("Starting new helpers\n");
	    helperStatefulOpenServers(hlp);
	}
    }
    if (srv->data != NULL)
	memPoolFree(hlp->datapool, srv->data);
    cbdataUnlock(srv->parent);
    cbdataFree(srv);
}


static void
helperHandleRead(int fd, void *data)
{
    int len;
    char *t = NULL;
    helper_server *srv = data;
    helper_request *r;
    helper *hlp = srv->parent;
    assert(fd == srv->rfd);
    assert(cbdataValid(data));
    statCounter.syscalls.sock.reads++;
    len = FD_READ_METHOD(fd, srv->buf + srv->offset, srv->buf_sz - srv->offset);
    fd_bytes(fd, len, FD_READ);
    debug(84, 5) ("helperHandleRead: %d bytes from %s #%d.\n",
	len, hlp->id_name, srv->index + 1);
    if (len <= 0) {
	if (len < 0)
	    debug(84, 1) ("helperHandleRead: FD %d read: %s\n", fd, xstrerror());
	comm_close(fd);
	return;
    }
    commSetSelect(srv->rfd, COMM_SELECT_READ, helperHandleRead, srv, 0);
    srv->offset += len;
    srv->buf[srv->offset] = '\0';
    r = srv->request;
    if (r == NULL) {
	/* someone spoke without being spoken to */
	debug(84, 1) ("helperHandleRead: unexpected read from %s #%d, %d bytes\n",
	    hlp->id_name, srv->index + 1, len);
	srv->offset = 0;
    } else if ((t = strchr(srv->buf, '\n'))) {
	/* end of reply found */
	debug(84, 3) ("helperHandleRead: end of reply found\n");
	*t = '\0';
	srv->flags.busy = 0;
	srv->offset = 0;
	srv->request = NULL;
	hlp->stats.replies++;
	srv->answer_time = current_time;
	hlp->stats.avg_svc_time =
	    intAverage(hlp->stats.avg_svc_time,
	    tvSubUsec(srv->dispatch_time, current_time),
	    hlp->stats.replies, REDIRECT_AV_FACTOR);
	if (cbdataValid(r->data))
	    r->callback(r->data, srv->buf);
	helperRequestFree(r);
	if (!srv->flags.shutdown) {
	    helperKickQueue(hlp);
	} else if (!srv->flags.closing) {
	    int wfd = srv->wfd;
	    srv->flags.closing = 1;
	    srv->wfd = -1;
	    comm_close(wfd);
	}
    }
}

static void
helperStatefulHandleRead(int fd, void *data)
{
    int len;
    char *t = NULL;
    helper_stateful_server *srv = data;
    helper_stateful_request *r;
    statefulhelper *hlp = srv->parent;
    assert(fd == srv->rfd);
    assert(cbdataValid(data));
    statCounter.syscalls.sock.reads++;
    len = FD_READ_METHOD(fd, srv->buf + srv->offset, srv->buf_sz - srv->offset);
    fd_bytes(fd, len, FD_READ);
    debug(84, 5) ("helperStatefulHandleRead: %d bytes from %s #%d.\n",
	len, hlp->id_name, srv->index + 1);
    if (len <= 0) {
	if (len < 0)
	    debug(84, 1) ("helperStatefulHandleRead: FD %d read: %s\n", fd, xstrerror());
	comm_close(fd);
	return;
    }
    commSetSelect(srv->rfd, COMM_SELECT_READ, helperStatefulHandleRead, srv, 0);
    srv->offset += len;
    srv->buf[srv->offset] = '\0';
    r = srv->request;
    if (r == NULL) {
	/* someone spoke without being spoken to */
	debug(84, 1) ("helperStatefulHandleRead: unexpected read from %s #%d, %d bytes\n",
	    hlp->id_name, srv->index + 1, len);
	srv->offset = 0;
    } else if ((t = strchr(srv->buf, '\n'))) {
	/* end of reply found */
	debug(84, 3) ("helperStatefulHandleRead: end of reply found\n");
	*t = '\0';
	srv->flags.busy = 0;
	srv->offset = 0;
	srv->request = NULL;
	hlp->stats.replies++;
	hlp->stats.avg_svc_time =
	    intAverage(hlp->stats.avg_svc_time,
	    tvSubMsec(srv->dispatch_time, current_time),
	    hlp->stats.replies, REDIRECT_AV_FACTOR);
	if (cbdataValid(r->data)) {
	    r->callback(r->data, srv, srv->buf);
	} else {
	    debug(84, 1) ("StatefulHandleRead: no callback data registered\n");
	}
	helperStatefulRequestFree(r);
    }
}

static void
Enqueue(helper * hlp, helper_request * r)
{
    dlink_node *link = memAllocate(MEM_DLINK_NODE);
    dlinkAddTail(r, link, &hlp->queue);
    hlp->stats.queue_size++;
    if (hlp->stats.queue_size < hlp->n_running)
	return;
    if (hlp->stats.queue_size > hlp->stats.max_queue_size)
	hlp->stats.max_queue_size = hlp->stats.queue_size;
    if (squid_curtime - hlp->last_queue_warn < 30)
	return;
    if (shutting_down || reconfiguring)
	return;
    debug(84, 1) ("WARNING: All %s processes are busy.\n", hlp->id_name);
    debug(84, 1) ("WARNING: up to %d pending requests queued\n", hlp->stats.max_queue_size);
    if (hlp->stats.queue_size > hlp->n_running * 2)
	fatalf("Too many queued %s requests (%d on %d)", hlp->id_name, hlp->stats.queue_size, hlp->n_running);
    if (squid_curtime - hlp->last_queue_warn < 300)
	debug(84, 1) ("Consider increasing the number of %s processes to at least %d in your config file.\n", hlp->id_name, hlp->n_running + hlp->stats.max_queue_size);
    hlp->last_queue_warn = squid_curtime;
    hlp->stats.max_queue_size = hlp->stats.queue_size;
}

static void
StatefulEnqueue(statefulhelper * hlp, helper_stateful_request * r)
{
    dlink_node *link = memAllocate(MEM_DLINK_NODE);
    dlinkAddTail(r, link, &hlp->queue);
    hlp->stats.queue_size++;
    if (hlp->stats.queue_size < hlp->n_running)
	return;
    if (hlp->stats.queue_size > hlp->stats.max_queue_size)
	hlp->stats.max_queue_size = hlp->stats.queue_size;
    if (hlp->stats.queue_size > hlp->n_running * 5)
	fatalf("Too many queued %s requests (%d on %d)", hlp->id_name, hlp->stats.queue_size, hlp->n_running);
    if (squid_curtime - hlp->last_queue_warn < 30)
	return;
    if (shutting_down || reconfiguring)
	return;
    debug(84, 1) ("WARNING: All %s processes are busy.\n", hlp->id_name);
    debug(84, 1) ("WARNING: up to %d pending requests queued\n", hlp->stats.max_queue_size);
    if (squid_curtime - hlp->last_queue_warn < 300)
	debug(84, 1) ("Consider increasing the number of %s processes to at least %d in your config file.\n", hlp->id_name, hlp->n_running + hlp->stats.max_queue_size);
    hlp->last_queue_warn = squid_curtime;
    hlp->stats.max_queue_size = hlp->stats.queue_size;
}

static helper_request *
Dequeue(helper * hlp)
{
    dlink_node *link;
    helper_request *r = NULL;
    if ((link = hlp->queue.head)) {
	r = link->data;
	dlinkDelete(link, &hlp->queue);
	memFree(link, MEM_DLINK_NODE);
	hlp->stats.queue_size--;
    }
    return r;
}

static helper_stateful_request *
StatefulDequeue(statefulhelper * hlp)
{
    dlink_node *link;
    helper_stateful_request *r = NULL;
    if ((link = hlp->queue.head)) {
	r = link->data;
	dlinkDelete(link, &hlp->queue);
	memFree(link, MEM_DLINK_NODE);
	hlp->stats.queue_size--;
    }
    return r;
}

static helper_server *
GetFirstAvailable(helper * hlp)
{
    dlink_node *n;
    helper_server *srv = NULL;
    if (hlp->n_running == 0)
	return NULL;
    for (n = hlp->servers.head; n != NULL; n = n->next) {
	srv = n->data;
	if (srv->flags.busy)
	    continue;
	if (srv->flags.shutdown)
	    continue;
	return srv;
    }
    return NULL;
}

static helper_stateful_server *
StatefulGetFirstAvailable(statefulhelper * hlp)
{
    dlink_node *n;
    helper_stateful_server *srv = NULL;
    debug(84, 5) ("StatefulGetFirstAvailable: Running servers %d.\n", hlp->n_running);
    if (hlp->n_running == 0)
	return NULL;
    for (n = hlp->servers.head; n != NULL; n = n->next) {
	srv = n->data;
	if (srv->flags.busy)
	    continue;
	if (srv->flags.reserved)
	    continue;
	if (srv->flags.shutdown)
	    continue;
	if ((hlp->IsAvailable != NULL) && (srv->data != NULL) && !(hlp->IsAvailable(srv->data)))
	    continue;
	return srv;
    }
    debug(84, 5) ("StatefulGetFirstAvailable: None available.\n");
    return NULL;
}


static void
helperDispatch(helper_server * srv, helper_request * r)
{
    helper *hlp = srv->parent;
    if (!cbdataValid(r->data)) {
	debug(84, 1) ("helperDispatch: invalid callback data\n");
	helperRequestFree(r);
	return;
    }
    assert(!srv->flags.busy);
    srv->flags.busy = 1;
    srv->request = r;
    srv->dispatch_time = current_time;
    comm_write(srv->wfd,
	r->buf,
	strlen(r->buf),
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	NULL);			/* free */
    debug(84, 5) ("helperDispatch: Request sent to %s #%d, %d bytes\n",
	hlp->id_name, srv->index + 1, (int) strlen(r->buf));
    srv->stats.uses++;
    hlp->stats.requests++;
}

static void
helperStatefulDispatch(helper_stateful_server * srv, helper_stateful_request * r)
{
    statefulhelper *hlp = srv->parent;
    if (!cbdataValid(r->data)) {
	debug(84, 1) ("helperStatefulDispatch: invalid callback data\n");
	helperStatefulRequestFree(r);
	return;
    }
    if (!r->buf) {
	if (cbdataValid(r->data)) {
	    r->callback(r->data, srv, NULL);
	} else {
	    debug(84, 1) ("helperStatefulDispatch: no callback data registered\n");
	}
	helperStatefulRequestFree(r);
	return;
    }
    debug(84, 9) ("helperStatefulDispatch busying helper %s #%d\n", hlp->id_name, srv->index + 1);
    srv->flags.busy = 1;
    srv->request = r;
    srv->dispatch_time = current_time;
    comm_write(srv->wfd,
	r->buf,
	strlen(r->buf),
	NULL,			/* Handler */
	NULL,			/* Handler-data */
	NULL);			/* free */
    debug(84, 5) ("helperStatefulDispatch: Request sent to %s #%d, %d bytes\n",
	hlp->id_name, srv->index + 1, (int) strlen(r->buf));
    srv->stats.uses++;
    hlp->stats.requests++;
}


static void
helperKickQueue(helper * hlp)
{
    helper_request *r;
    helper_server *srv;
    while ((srv = GetFirstAvailable(hlp)) && (r = Dequeue(hlp)))
	helperDispatch(srv, r);
}

static void
helperStatefulKickQueue(statefulhelper * hlp)
{
    helper_stateful_request *r;
    helper_stateful_server *srv;
    while ((srv = StatefulGetFirstAvailable(hlp)) && (r = StatefulDequeue(hlp))) {
	srv->flags.reserved = 1;
	helperStatefulDispatch(srv, r);
    }
}

static void
helperRequestFree(helper_request * r)
{
    cbdataUnlock(r->data);
    xfree(r->buf);
    memFree(r, MEM_HELPER_REQUEST);
}

static void
helperStatefulRequestFree(helper_stateful_request * r)
{
    cbdataUnlock(r->data);
    xfree(r->buf);
    memFree(r, MEM_HELPER_STATEFUL_REQUEST);
}
