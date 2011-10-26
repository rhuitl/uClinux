#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "fileblock.h"

static int fd = -1;

unsigned long fb_len()
{
	struct stat st;

	if (fd < 0)
		return 0;

	if (fstat(fd, &st) < 0)
		return 0;

	return st.st_size;
}

int fb_seek_set(unsigned long pos)
{
	if (lseek(fd, pos, SEEK_SET) != pos)
		return -1;

	return 0;
}

int fb_seek_end(unsigned long offset)
{
	if (lseek(fd, -(off_t)offset, SEEK_END) < 0)
		return -1;

	return 0;
}

int fb_seek_inc(unsigned long offset)
{
	if (lseek(fd, offset, SEEK_CUR) < 0)
		return -1;

	return 0;
}

int fb_seek_dec(unsigned long offset)
{
	if (lseek(fd, -(off_t)offset, SEEK_CUR) < 0)
		return -1;

	return 0;
}

unsigned long fb_tell(void)
{
	return lseek(fd, 0, SEEK_CUR);
}

void fb_throw(unsigned long maxlen, void (* f)(void *, unsigned long))
{
}

int fb_write(const void *data, unsigned long len)
{
	if (fd < 0) {
		fd = open("fileblock_file.test", O_RDWR | O_CREAT | O_TRUNC, 0400);
		if (fd < 0)
			return -1;
	}

	if (write(fd, data, len) != len)
		return -1;

	return 0;
}

int fb_peek(void *data, unsigned long len)
{
	unsigned long pos;
	int ret;

	pos = fb_tell();
	ret = fb_read(data, len);
	fb_seek_set(pos);
	return ret;
}

int fb_read(void *data, unsigned long len)
{
	return read(fd, data, len);
}

void *fb_read_block(unsigned long *len)
{
	static char buf[4096];

	*len = read(fd, buf, sizeof(buf));
	if (*len <= 0)
		return NULL;

	return buf;
}

int fb_trim(unsigned long len)
{
	unsigned long file_length = fb_len();

	if (len > file_length)
		return -1;

	if (ftruncate(fd, file_length - len) != 0)
		return -1;

	return 0;
}
