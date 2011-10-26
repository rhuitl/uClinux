/* error logging functions
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: log.c,v 1.46 2002/03/15 22:30:16 dhr Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>	/* used only if MSG_NOSIGNAL not defined */

#include <freeswan.h>

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "connections.h"	/* needs id.h */
#include "whack.h"	/* needs connections.h */

bool
    log_to_stderr = TRUE,	/* should log go to stderr? */
    log_to_syslog = TRUE;	/* should log go to syslog? */

/* Context for logging.
 *
 * Global variables: must be carefully adjusted at transaction boundaries!
 * If the context provides a whack file descriptor, messages
 * should be copied to it -- see whack_log()
 */
int whack_log_fd = NULL_FD;	/* only set during whack_handle() */
struct state *cur_state = NULL;	/* current state, for diagnostics */
struct connection *cur_connection = NULL;	/* current connection, for diagnostics */
const ip_address *cur_from = NULL;	/* source of current current message */
u_int16_t cur_from_port;	/* host order */

void
init_log(void)
{
    if (log_to_stderr)
	setbuf(stderr, NULL);
    if (log_to_syslog)
	openlog("Pluto", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_AUTHPRIV);
}

void
close_log(void)
{
    if (log_to_syslog)
	closelog();
}

/* Sanitize character string in situ: turns dangerous characters into \OOO.
 * With a bit of work, we could use simpler reps for \\, \r, etc.,
 * but this is only to protect against something that shouldn't be used.
 * Truncate resulting string to what fits in buffer.
 */
static size_t
sanitize(char *buf, size_t size)
{
#   define UGLY_WIDTH	4	/* width for ugly character: \OOO */
    size_t len;
    size_t added = 0;
    char *p;

    passert(size >= UGLY_WIDTH);	/* need room to swing cat */

    /* find right side of string to be sanitized and count
     * number of columns to be added.  Stop on end of string
     * or lack of room for more result.
     */
    for (p = buf; *p != '\0' && &p[added] < &buf[size - UGLY_WIDTH]; )
    {
	unsigned char c = *p++;

	if (c == '\\' || !isprint(c))
	    added += UGLY_WIDTH - 1;
    }

    /* at this point, p points after last original character to be
     * included.  added is how many characters are added to sanitize.
     * so p[added] will point after last sanitized character.
     */

    p[added] = '\0';
    len = &p[added] - buf;

    /* scan backwards, copying characters to their new home
     * and inserting the expansions for ugly characters.
     * It is finished when no more shifting is required.
     * This is a predecrement loop.
     */
    while (added != 0)
    {
	char fmtd[UGLY_WIDTH + 1];
	unsigned char c;

	while ((c = *--p) != '\\' && isprint(c))
	    p[added] = c;
	added -= UGLY_WIDTH - 1;
	snprintf(fmtd, sizeof(fmtd), "\\%03o", c);
	memcpy(p + added, fmtd, UGLY_WIDTH);
    }
    return len;
#   undef UGLY_WIDTH
}

/* format a string for the log, with suitable prefixes.
 * A format starting with ~ indicates that this is a reprocessing
 * of the message, so prefixing and quoting is suppressed.
 */
static void
fmt_log(char *buf, size_t buf_len, const char *fmt, va_list ap)
{
    bool reproc = *fmt == '~';
    size_t ps;
    struct connection *c = cur_state != NULL ? cur_state->st_connection
	: cur_connection;

    buf[0] = '\0';
    if (reproc)
	fmt++;	/* ~ at start of format suppresses this prefix */
    else if (c != NULL)
    {
	/* start with name of connection */
	char *const be = buf + buf_len;
	char *bp = buf;

	snprintf(bp, be - bp, "\"%s\"", c->name);
	bp += strlen(bp);

	/* if it fits, put in any connection instance information */
	if (be - bp > CONN_INST_BUF)
	{
	    fmt_conn_instance(c, bp);
	    bp += strlen(bp);
	}

	if (cur_state != NULL)
	{
	    /* state number */
	    snprintf(bp, be - bp, " #%lu", cur_state->st_serialno);
	    bp += strlen(bp);
	}
	snprintf(bp, be - bp, ": ");
    }
    else if (cur_from != NULL)
    {
	/* peer's IP address */
	/* Note: must not use ip_str() because our caller might! */
	char ab[ADDRTOT_BUF];

	(void) addrtot(cur_from, 0, ab, sizeof(ab));
	snprintf(buf, buf_len, "packet from %s:%u: "
	    , ab, (unsigned)cur_from_port);
    }

    ps = strlen(buf);
    vsnprintf(buf + ps, buf_len - ps, fmt, ap);
    if (!reproc)
	(void)sanitize(buf, buf_len);
}

void
log(const char *message, ...)
{
    va_list args;
    char m[1024];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    if (log_to_stderr)
	fprintf(stderr, "%s\n", m);
    if (log_to_syslog)
	syslog(LOG_WARNING, "%s", m);

    whack_log(RC_LOG, "~%s", m);
}

void
loglog(int mess_no, const char *message, ...)
{
    va_list args;
    char m[1024];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    if (log_to_stderr)
	fprintf(stderr, "%s\n", m);
    if (log_to_syslog)
	syslog(LOG_WARNING, "%s", m);

    whack_log(mess_no, "~%s", m);
}

void
log_errno_routine(int e, const char *message, ...)
{
    va_list args;
    char m[1024];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    if (log_to_stderr)
	fprintf(stderr, "ERROR: %s. Errno %d: %s\n", m, e, strerror(e));
    if (log_to_syslog)
	syslog(LOG_ERR, "ERROR: %s. Errno %d: %s", m, e, strerror(e));

    whack_log(RC_LOG_SERIOUS
	, "~ERROR: %s. Errno %d: %s", m, e, strerror(e));
}

void
exit_log(const char *message, ...)
{
    va_list args;
    char m[1024];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    if (log_to_stderr)
	fprintf(stderr, "FATAL ERROR: %s\n", m);
    if (log_to_syslog)
	syslog(LOG_ERR, "FATAL ERROR: %s", m);

    whack_log(RC_LOG_SERIOUS, "~FATAL ERROR: %s", m);

    exit_pluto(1);
}

void
exit_log_errno_routine(int e, const char *message, ...)
{
    va_list args;
    char m[1024];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    if (log_to_stderr)
	fprintf(stderr, "FATAL ERROR: %s. Errno %d: %s\n", m, e, strerror(e));
    if (log_to_syslog)
	syslog(LOG_ERR, "FATAL ERROR: %s. Errno %d: %s", m, e, strerror(e));

    whack_log(RC_LOG_SERIOUS
	, "~FATAL ERROR: %s. Errno %d: %s", m, e, strerror(e));

    exit_pluto(1);
}

/* emit message to whack.
 * form is "ddd statename text" where
 * - ddd is a decimal status code (RC_*) as described in whack.h
 * - text is a human-readable annotation
 */
void
whack_log(int mess_no, const char *message, ...)
{
    int wfd = whack_log_fd != NULL_FD ? whack_log_fd
	: cur_state != NULL ? cur_state->st_whack_sock
	: NULL_FD;

    if (wfd != NULL_FD)
    {
	va_list args;
	char m[1024];	/* longer messages will be truncated */
	int prelen = snprintf(m, sizeof(m), "%03d ", mess_no);
	size_t len;

	passert(prelen >= 0);

	va_start(args, message);
	fmt_log(m+prelen, sizeof(m)-prelen, message, args);
	va_end(args);

	len = strlen(m);
	m[len] = '\n';	/* don't need NUL, do need NL */

	/* write to whack socket, but suppress possible SIGPIPE */
#ifdef MSG_NOSIGNAL	/* depends on version of glibc??? */
	(void) send(wfd, m, len + 1, MSG_NOSIGNAL);
#else /* !MSG_NOSIGNAL */
	{
	    int r;
	    struct sigaction act
		, oldact;

	    act.sa_handler = SIG_IGN;
	    sigemptyset(&act.sa_mask);
	    act.sa_flags = 0;	/* no nothing */
	    r = sigaction(SIGPIPE, &act, &oldact);
	    passert(r == 0);

	    (void) write(wfd, m, len + 1);

	    r = sigaction(SIGPIPE, &oldact, NULL);
	    passert(r == 0);
	}
#endif /* !MSG_NOSIGNAL */
    }
}

/* Build up a diagnostic in a static buffer.
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 */
char diag_space[sizeof(diag_space)];

err_t
builddiag(const char *fmt, ...)
{
    static char diag_space[1024];	/* longer messages will be truncated */
    char t[sizeof(diag_space)];	/* build result here first */
    va_list args;

    va_start(args, fmt);
    t[0] = '\0';	/* in case nothing terminates string */
    vsnprintf(t, sizeof(t), fmt, args);
    va_end(args);
    strcpy(diag_space, t);
    return diag_space;
}

/* Debugging message support */

#ifdef DEBUG

void
passert_fail(const char *pred_str, const char *file_str, unsigned long line_no)
{
    /* we will get a possibly unplanned prefix.  Hope it works */
    loglog(RC_LOG_SERIOUS, "ASSERTION FAILED at %s:%lu: %s", file_str, line_no, pred_str);
    abort();	/* exiting correctly doesn't always work */
}

unsigned int
    base_debugging = DBG_NONE,	/* default to reporting nothing */
    cur_debugging =  DBG_NONE;

void
extra_debugging(const struct connection *c)
{
    if (c->extra_debugging != 0)
    {
	log("enabling for connection: %s"
	    , bitnamesof(debug_bit_names, c->extra_debugging & ~cur_debugging));
	cur_debugging |= c->extra_debugging;
    }
}

/* log a debugging message (prefixed by "| ") */

void
DBG_log(const char *message, ...)
{
    va_list args;
    char m[1024];	/* longer messages will be truncated */

    va_start(args, message);
    vsnprintf(m, sizeof(m), message, args);
    va_end(args);

    (void)sanitize(m, sizeof(m));

    if (log_to_stderr)
	fprintf(stderr, "| %s\n", m);
    if (log_to_syslog)
	syslog(LOG_DEBUG, "| %s", m);
}

/* dump raw bytes in hex to stderr (for lack of any better destination) */

void
DBG_dump(const char *label, const void *p, size_t len)
{
#   define DUMP_LABEL_WIDTH 20	/* arbitrary modest boundary */
#   define DUMP_WIDTH	(4 * (1 + 4 * 3) + 1)
    char buf[DUMP_LABEL_WIDTH + DUMP_WIDTH];
    char *bp;
    const unsigned char *cp = p;

    bp = buf;

    if (label != NULL && label[0] != '\0')
    {
	/* Handle the label.  Care must be taken to avoid buffer overrun. */
	size_t llen = strlen(label);

	if (llen + 1 > sizeof(buf))
	{
	    DBG_log("%s", label);
	}
	else
	{
	    strcpy(buf, label);
	    if (buf[llen-1] == '\n')
	    {
		buf[llen-1] = '\0';	/* get rid of newline */
		DBG_log("%s", buf);
	    }
	    else if (llen < DUMP_LABEL_WIDTH)
	    {
		bp = buf + llen;
	    }
	    else
	    {
		DBG_log("%s", buf);
	    }
	}
    }

    do {
	int i, j;

	for (i = 0; len!=0 && i!=4; i++) {
	    *bp++ = ' ';
	    for (j = 0; len!=0 && j!=4; len--, j++)
	    {
		static const char hexdig[] = "0123456789abcdef";

		*bp++ = ' ';
		*bp++ = hexdig[(*cp >> 4) & 0xF];
		*bp++ = hexdig[*cp & 0xF];
		cp++;
	    }
	}
	*bp = '\0';
	DBG_log("%s", buf);
	bp = buf;
    } while (len != 0);
#   undef DUMP_LABEL_WIDTH
#   undef DUMP_WIDTH
}

#endif /* DEBUG */


/* ip_str: a simple to use variant of addrtot.
 * It stores its result in a static buffer.
 * This means that newer calls overwrite the storage of older calls.
 * Note: this is not used in any of the logging functions, so their
 * callers may use it.
 */
const char *
ip_str(const ip_address *src)
{
    static char buf[ADDRTOT_BUF];

    addrtot(src, 0, buf, sizeof(buf));
    return buf;
}
