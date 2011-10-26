#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <assert.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "kmp.h"
#include "cgiparse.h"

#define MULTIPART_FORM_DATA "multipart/form-data;"
#define CONTENT_DISPOSITION "Content-Disposition:"
#define CONTENT_TYPE "Content-Type:"
#define OCTET_STREAM "application/octet-stream"

#ifdef DEBUG_CGI
#define debug(args...) syslog(LOG_INFO, args)
#else
#define debug(args...)
#endif

#define MAX_HEADER_SIZE 128
#define MAX_NAME_SIZE  64
#define MAX_CONTENT_TYPE 54

#define OS_BUF_SIZE (4096 + MAX_HEADER_SIZE)

typedef struct {
	int timeout;
	char buf[OS_BUF_SIZE];
	size_t len; /* length of data in buf */
	off_t pos; /* offset within section data of last valid byte in buf */
	size_t consumed; /* length of data used by matcher */
	int in_section; /* sending current section to writer */
	output_buffer_function *writer;
	char name[MAX_NAME_SIZE];
	char content_type[MAX_CONTENT_TYPE];
} output_section_t;

static int process_section(output_section_t *os);

static void set_nonblock(int fd)
{
	int val;

	val = fcntl(fd, F_GETFL);
	if (val >= 0 && !(val & O_NONBLOCK))
		fcntl(fd, F_SETFL, val | O_NONBLOCK);
}

/*
 * Reads data into the end of the buffer.
 * Returns number of byes read.
 */
static int os_read(output_section_t *os)
{
	struct pollfd fds[1];
	int ret;

	fds[0].fd = 0;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	do
		ret = poll(fds, 1, 30);
	while (ret < 0 && errno == EINTR);
	if (ret <= 0 || !(fds[0].revents & POLLIN)) {
		if (ret == 0)
			os->timeout = 1;
		return 0;
	}

	do
		ret = read(0, os->buf + os->len, sizeof(os->buf) - os->len);
	while (ret < 0 && errno == EINTR);
	if (ret <= 0)
		return 0;

	os->len += ret;
	os->pos += ret;
	return ret;
}

/*
 * Read into buffer until a newline is found.
 * Note: searches any existing data in the buffer, so discard
 * any previously processed data before calling.
 * Returns offset of newline, or 0 if buffer is full before found.
 */
static ssize_t os_getline(output_section_t *os)
{
	size_t len = 0;
	char *p;

	for (;;) {
		p = memchr(os->buf + len, '\n', os->len - len);
		if (p)
			return p - os->buf + 1;
		len = os->len;
		if (os_read(os) <= 0)
			return 0;
	}
}

/*
 * Discards the specified number of byes from the front of the buffer.
 */
static void os_discard(output_section_t *os, size_t len)
{
	memmove(os->buf, os->buf + len, os->len - len);
	os->len -= len;
}

/*
 * Simple wrapper around os_read that passes any previously processed
 * data to os->writer and then discards it to make room in
 * the buffer, while ensuring at least MAX_HEADER_SIZE bytes remain.
 * Returns the number of new data bytes in the buffer.
 */
static int getter_section(const char **text, void *cookie)
{
	output_section_t *os = cookie;
	size_t prevconsumed;

	if (os->consumed < os->len)
		goto done;

	if (os->len == sizeof(os->buf)) {
		if (os->consumed <= MAX_HEADER_SIZE)
			goto done;

		if (os->in_section) {
			os->writer(os->name, os->content_type, os->buf, os->consumed - MAX_HEADER_SIZE, os->pos - os->len);

		}
		os_discard(os, os->consumed - MAX_HEADER_SIZE);
		os->consumed = MAX_HEADER_SIZE;
	}

	if (os_read(os) <= 0)
		return 0;

done:
	prevconsumed = os->consumed;
	os->consumed = os->len;
	*text = os->buf + prevconsumed;
	return os->consumed - prevconsumed;
}

int cgi_extract_sections(output_buffer_function *writer)
{
	int content_length;
	const char *p;
	char *boundary;
	int boundary_length;
	int match;
	output_section_t os;

	p = getenv("REQUEST_METHOD");
	if (!p || strcmp(p, "POST") != 0) {
		syslog(LOG_WARNING, "cgi_filefetch not POST");
		return(CGIPARSE_ERR_FORMAT);
	}

	p = getenv("CONTENT_LENGTH");
	if (!p || ((content_length = atoi(p)) == 0)) {
		syslog(LOG_WARNING, "cgi_filefetch bad content length");
		return(CGIPARSE_ERR_DATA);
	}

	p = getenv("CONTENT_TYPE");
	if (!p || strncmp(p, MULTIPART_FORM_DATA, sizeof(MULTIPART_FORM_DATA) - 1) != 0) {
		syslog(LOG_WARNING, "cgi_filefetch not type: %s", MULTIPART_FORM_DATA);
		return(CGIPARSE_ERR_DATA);
	}

	/* Now search for boundary=XXX */
	p = strstr(p, "boundary=");
	if (!p) {
		syslog(LOG_WARNING, "cgi_filefetch bad or missing boundary specification");
		return(CGIPARSE_ERR_DATA);
	}
	p = strchr(p, '=') + 1;
	debug("Got boundary=[%s]\n", p);

	/* Now search for --<boundary>
	 * Note that we don't search for \r\n--<boundary> since
	 * sometimes?? the first \r\n is missing
	 */

	boundary_length = strlen(p) + 2;
	boundary = alloca(boundary_length + 1);
	sprintf(boundary, "--%s", p);

	os.timeout = 0;
	os.len = 0;
	os.pos = 0;
	os.consumed = 0;
	os.in_section = 0;
	os.writer = writer;

	set_nonblock(0);

	/* Now iterate through each item separated by the boundary */
	while ((match = KMP(boundary, boundary_length, getter_section, &os)) >= 0) {
		debug("Found match at %d\n", match - boundary_length);

		/* Flush all the bytes up until the match. */
		os.consumed = os.len - (os.pos - match);
		if (os.in_section) {
			/* We have been outputting this section. Back up by the boundary length
			 * (plus 2 for the \r\n) and flush the buffer
			 */
			debug("reached end of section, match=%d, os.len=%d, os.pos=%d, boundary_length=%d\n", match, (int)os.len, (int)os.pos, boundary_length);
			assert(os.consumed >= boundary_length + 2);
			os.writer(os.name, os.content_type, os.buf,
					os.consumed - boundary_length - 2,
					os.pos - os.len);
		}
		os_discard(&os, os.consumed);
		os.consumed = 0;

		while (os.len < 2)
			if (os_read(&os) <= 0)
				goto err;
		char ch1 = os.buf[0];
		char ch2 = os.buf[1];
		os_discard(&os, 2);

		if (ch1 == '\r' && ch2 == '\n') {
			/* we are at a boundary, so process this section */
			if (process_section(&os) <= 0)
				goto err;
		}
		else if (ch1 == '-' && ch2 == '-') {
			debug("This is the last section\n");
			return CGIPARSE_ERR_NONE;
		}
		else {
			debug("Warning: Ignoring section with unknown terminator: '%c%c'\n", ch1, ch2);
		}
		os.pos = os.len;
	}

err:
	if (os.timeout) {
		return CGIPARSE_ERR_TIMEDOUT;
	} else {
		return CGIPARSE_ERR_DATA;
	}
}

/**
 * Returns 1 if found a valid section or 0 if not.
 *
 * Also sets os->in_section, os->name, os->content_type.
 */
static int process_section(output_section_t *os)
{
	/* Need to read lines ending in \r\n, processing the headers
	 * Headers are terminated by a blank line
	 */
	char *pt;
	size_t len;

	os->name[0] = 0;
	os->content_type[0] = 0;
	os->in_section = 0;

	while ((len = os_getline(os)) > 0) {
		os->buf[len - 1] = '\0';
		if (os->buf[0] == '\r') {
			/* Reached end of headers */
			debug("End of headers\n");
			os_discard(os, len);
			return 1;
		}
		/* Strip off any \r\n */
		pt = strchr(os->buf, '\r');
		if (pt) {
			*pt = 0;
		}
		debug("HEADER: %s\n", os->buf);

		if (strncmp(os->buf, CONTENT_DISPOSITION, sizeof(CONTENT_DISPOSITION) - 1) == 0) {
			pt = strstr(os->buf, "name=\"");
			if (!pt) {
				syslog(LOG_WARNING, "Warning: %s with no name\n", CONTENT_DISPOSITION);
			}
			else {
				char *end;
				pt += 6;
				end = strchr(pt, '"');
				if (end) {
					*end = 0;
				}
				snprintf(os->name, sizeof(os->name), "%s", pt);
				os->in_section = 1;
				os->writer(os->name, os->content_type, 0, 0, 0);
			}
		}
		else if (strncmp(os->buf, CONTENT_TYPE, sizeof(CONTENT_TYPE) - 1) == 0) {
			pt = os->buf + sizeof(CONTENT_TYPE);

			snprintf(os->content_type, sizeof(os->content_type), "%s", pt);
		}
		/* Ignore other headers */
		os_discard(os, len);
	}

	return 0;
}
