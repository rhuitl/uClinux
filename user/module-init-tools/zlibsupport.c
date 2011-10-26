/* Support for compressed modules.  Willy Tarreau <willy@meta-x.org>
 * did the support for modutils, Andrey Borzenkov <arvidjaar@mail.ru>
 * ported it to module-init-tools, and I said it was too ugly to live
 * and rewrote it 8).
 *
 * (C) 2003 Rusty Russell, IBM Corporation.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include "zlibsupport.h"
#include "testing.h"

#ifdef CONFIG_USE_ZLIB
#include <zlib.h>

void *grab_contents(gzFile *gzfd, unsigned long *size)
{
	unsigned int max = 16384;
	void *buffer = malloc(max);
	int ret;

	if (!buffer)
		return NULL;

	*size = 0;
	while ((ret = gzread(gzfd, buffer + *size, max - *size)) > 0) {
		*size += ret;
		if (*size == max) {
			buffer = realloc(buffer, max *= 2);
			if (!buffer)
				return NULL;
		}
	}
	if (ret < 0) {
		free(buffer);
		buffer = NULL;
	}
	return buffer;
}

void *grab_fd(int fd, unsigned long *size)
{
	gzFile gzfd;

	gzfd = gzdopen(fd, "rb");
	if (!gzfd)
		return NULL;

	/* gzclose(gzfd) would close fd, which would drop locks.
	   Don't blame zlib: POSIX locking semantics are so horribly
	   broken that they should be ripped out. */
	return grab_contents(gzfd, size);
}

/* gzopen handles uncompressed files transparently. */
void *grab_file(const char *filename, unsigned long *size)
{
	gzFile gzfd;
	void *buffer;

	gzfd = gzopen(filename, "rb");
	if (!gzfd)
		return NULL;
	buffer = grab_contents(gzfd, size);
	gzclose(gzfd);
	return buffer;
}

void release_file(void *data, unsigned long size)
{
	free(data);
}
#else /* ... !CONFIG_USE_ZLIB */

void *grab_fd(int fd, unsigned long *size)
{
	struct stat st;
	void *map;

	fstat(fd, &st);
	*size = st.st_size;
	map = mmap(0, *size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED)
		map = NULL;
	return map;
}

void *grab_file(const char *filename, unsigned long *size)
{
	int fd;
	void *map;

	fd = open(filename, O_RDONLY, 0);
	if (fd < 0)
		return NULL;
	map = grab_fd(fd, size);
	close(fd);
	return map;
}

void release_file(void *data, unsigned long size)
{
	munmap(data, size);
}
#endif
