#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fileblock.h"

struct fileblock {
	void *data;
	unsigned long length;
	unsigned long maxlength;
	struct fileblock *next;
};

static unsigned long file_length;

static struct fileblock *first;
static unsigned long first_pos;

static struct fileblock *current;
static unsigned long current_pos;	/* includes current_offset */
static unsigned long current_offset;

static struct fileblock *thrown;

#define	BLOCK_OVERHEAD	16
#define	block_len	(_block_len - BLOCK_OVERHEAD)
int _block_len = 8192;

#if 0
#define debug fprintf
#else
#define debug(...) do { } while (0)
#endif

unsigned long fb_len()
{
	return file_length;
}

int fb_seek_set(unsigned long pos)
{
	debug(stderr, "fb_seek_set(%ld), first %ld/%ld\n", pos, first_pos, file_length);

	if (pos < first_pos || pos >= file_length)
		return -1;

	current = first;
	current_pos = first_pos;
	current_offset = 0;
	return fb_seek_inc(pos - current_pos);
}

int fb_seek_end(unsigned long offset)
{
	debug(stderr, "fb_seek_end(%ld)\n", offset);

	if (offset > file_length)
		return -1;

	return fb_seek_set(file_length - offset);
}

int fb_seek_inc(unsigned long offset)
{
	unsigned long l;

	debug(stderr, "fb_seek_inc(%ld), current %ld/%ld\n", offset, current_pos, file_length);

	if (offset >= file_length - current_pos)
		return -1;

	while ((l = current->length - current_offset) < offset) {
		offset -= l;
		current_pos += l;
		current_offset = 0;
		current = current->next;
	}

	current_pos += offset;
	current_offset += offset;
	return 0;
}

int fb_seek_dec(unsigned long offset)
{
	debug(stderr, "fb_seek_dec(%ld), current %ld\n", offset, current_pos);

	if (offset > current_pos)
		return -1;

	if (offset <= current_offset) {
		current_pos -= offset;
		current_offset -= offset;
		return 0;
	}

	return fb_seek_set(current_pos - offset);
}

unsigned long fb_tell(void)
{
	return current_pos;
}

void fb_throw(unsigned long maxlen, void (* f)(void *, unsigned long))
{
	struct fileblock *fb;

	if (!first)
		return;

	while (file_length - first_pos - first->length > maxlen) {
		debug(stderr, "fb_throw(%ld), first %ld/%ld, length %ld\n", maxlen, first_pos, first->length, file_length);

		fb = first;
		first = first->next;

		fb->next = thrown;
		thrown = fb;

		first_pos += fb->length;
		if (current_pos < first_pos) {
			current = first;
			current_pos = first_pos;
		}

		f(fb->data, fb->length);
	}
}

static struct fileblock *fb_alloc(void)
{
	struct fileblock *fb;

	if (thrown) {
		fb = thrown;
		thrown = thrown->next;
		fb->length = 0;
		return fb;
	}

	fb = malloc(sizeof(*fb));
	if (!fb)
		return NULL;

	for (;;) {
		fb->data = malloc(block_len);
		if (fb->data)
			break;

		/* Halve the block size and try again, down to 1 page */
		if (_block_len < 4096) {
			free(fb);
			return NULL;
		}
		_block_len /= 2;
	}

	fb->next = NULL;
	fb->length = 0;
	fb->maxlength = block_len;
	return fb;
}

int fb_write(const void *data, unsigned long len)
{
	unsigned long l;
	void *p;

	debug(stderr, "fb_write(%ld), current %ld\n", len, current_pos);

	if (!first) {
		first = fb_alloc();
		if (!first)
			return -1;
		current = first;
	}

	for (;;) {
		p = current->data + current_offset;
		l = current->maxlength - current_offset;
		if (l > len)
			l = len;

		memcpy(p, data, l);
		data += l;
		len -= l;

		current_pos += l;
		if (file_length < current_pos)
			file_length = current_pos;

		current_offset += l;
		if (current->length < current_offset)
			current->length = current_offset;

		if (len == 0)
			return 0;

		if (!current->next) {
			current->next = fb_alloc();
			if (!current->next)
				return -1;
		}

		current = current->next;
		current_offset = 0;
	}
}

int fb_peek(void *data, unsigned long len)
{
	struct fileblock *fb;
	unsigned long fb_pos;
	unsigned long fb_offset;
	int ret;

	fb = current;
	fb_pos = current_pos;
	fb_offset = current_offset;
	ret = fb_read(data, len);
	current = fb;
	current_pos = fb_pos;
	current_offset = fb_offset;
	return ret;
}

int fb_read(void *data, unsigned long len)
{
	unsigned long readlen;
	unsigned long l;
	void *p;

	debug(stderr, "fb_read(%ld), current %ld\n", len, current_pos);

	if (file_length - current_pos < len)
		len = file_length - current_pos;

	readlen = len;
	for (;;) {
		p = current->data + current_offset;
		l = current->length - current_offset;
		if (l > len)
			l = len;

		memcpy(data, p, l);
		data += l;
		len -= l;

		current_pos += l;
		current_offset += l;

		if (len == 0)
			return readlen;

		current = current->next;
		current_offset = 0;
	}
}

void *fb_read_block(unsigned long *len)
{
	unsigned long l;
	void *p;

	debug(stderr, "fb_read_block(), current %ld/%ld\n", current_pos, current->length);

	if (current_pos >= file_length)
		return NULL;

	if (current_offset >= current->length) {
		current = current->next;
		current_offset = 0;
	}

	p = current->data + current_offset;
	l = current->length - current_offset;

	current_pos += l;
	current_offset += l;

	*len = l;
	return p;
}

int fb_trim(unsigned long len)
{
	struct fileblock *fb;
	struct fileblock *fbnext;
	unsigned long fb_pos;

	debug(stderr, "fb_trim(%ld), length %ld\n", len, file_length);

	if (len > file_length - first_pos)
		return -1;

	file_length -= len;
	for (fb = first, fb_pos = first_pos;
			fb_pos + fb->length < file_length;
			fb_pos += fb->length, fb = fb->next);

	fb->length = file_length - fb_pos;

	while (fb->next) {
		fbnext = fb->next;
		fb->next = fbnext->next;
		free(fbnext->data);
		free(fbnext);
	}

	if (current_pos > file_length)
		fb_seek_set(file_length);

	return 0;
}
