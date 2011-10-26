/*
 * Copyright (C) 2007 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * Author: Adrian Hunter
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/mman.h>

#include "tests.h"

/* Structures to store data written to the test file system,
   so that we can check whether the file system is correct. */

struct write_info /* Record of random data written into a file */
{
	struct write_info *next;
	off_t offset; /* Where in the file the data was written */
	size_t size; /* Number of bytes written */
	unsigned random_seed; /* Seed for rand() to create random data */
	off_t random_offset; /* Call rand() this number of times first */
	int trunc; /* Records a truncation (raw_writes only) */
};

struct dir_entry_info;

struct file_info /* Each file has one of these */
{
	char *name; /* Original name */
	struct write_info *writes; /* Record accumulated writes to the file */
	struct write_info *raw_writes;
				/* Record in order all writes to the file */
	struct fd_info *fds; /* All open file descriptors for this file */
	struct dir_entry_info *links;
	int link_count;
	off_t length;
	int deleted; /* File has been deleted but is still open */
	int no_space_error; /* File has incurred a ENOSPC error */
	uint64_t check_run_no; /* Run number used when checking */
};

struct symlink_info /* Each symlink has one of these */
{
	char *target_pathname;
	struct dir_entry_info *entry; /* dir entry of this symlink */
};

struct dir_info /* Each directory has one of these */
{
	char *name;
	struct dir_info *parent; /* Parent directory or null
					for our top directory */
	unsigned number_of_entries;
	struct dir_entry_info *first;
	struct dir_entry_info *entry; /* Dir entry of this dir */
};

struct dir_entry_info /* Each entry in a directory has one of these */
{
	struct dir_entry_info *next; /* List of entries in directory */
	struct dir_entry_info *prev; /* List of entries in directory */
	struct dir_entry_info *next_link; /* List of hard links for same file */
	struct dir_entry_info *prev_link; /* List of hard links for same file */
	char *name;
	struct dir_info *parent; /* Parent directory */
	char type; /* f => file, d => dir, s => symlink */
	int checked; /* Temporary flag used when checking */
	union entry_
	{
		struct file_info *file;
		struct dir_info *dir;
		struct symlink_info *symlink;
		void *target;
	} entry;
};

struct fd_info /* We keep a number of files open */
{
	struct fd_info *next;
	struct file_info *file;
	int fd;
};

struct open_file_info /* We keep a list of open files */
{
	struct open_file_info *next;
	struct fd_info *fdi;
};

static struct dir_info *top_dir = NULL; /* Our top directory */

static struct open_file_info *open_files = NULL; /* We keep a list of
							open files */
static size_t open_files_count = 0;

static int grow   = 1; /* Should we try to grow files and directories */
static int shrink = 0; /* Should we try to shrink files and directories */
static int full   = 0; /* Flag that the file system is full */
static uint64_t operation_count = 0; /* Number of operations used to fill
                                        up the file system */
static uint64_t initial_free_space = 0; /* Free space on file system when
					   test starts */
static unsigned log10_initial_free_space = 0; /* log10 of initial_free_space */

static int check_nospc_files = 0; /* Also check data in files that incurred a
				     "no space" error */

static int can_mmap = 0; /* Can write via mmap */

static long mem_page_size; /* Page size for mmap */

static uint64_t check_run_no;

static char *copy_string(const char *s)
{
	char *str;

	if (!s)
		return NULL;
	str = (char *) malloc(strlen(s) + 1);
	CHECK(str != NULL);
	strcpy(str, s);
	return str;
}

static char *cat_strings(const char *a, const char *b)
{
	char *str;
	size_t sz;

	if (a && !b)
		return copy_string(a);
	if (b && !a)
		return copy_string(b);
	if (!a && !b)
		return NULL;
	sz = strlen(a) + strlen(b) + 1;
	str = (char *) malloc(sz);
	CHECK(str != NULL);
	strcpy(str, a);
	strcat(str, b);
	return str;
}

static char *cat_paths(const char *a, const char *b)
{
	char *str;
	size_t sz;
	int as, bs;
	size_t na, nb;

	if (a && !b)
		return copy_string(a);
	if (b && !a)
		return copy_string(b);
	if (!a && !b)
		return NULL;

	as = 0;
	bs = 0;
	na = strlen(a);
	nb = strlen(b);
	if (na && a[na - 1] == '/')
		as = 1;
	if (nb && b[0] == '/')
		bs = 1;
	if ((as && !bs) || (!as && bs))
		return cat_strings(a, b);
	if (as && bs)
		return cat_strings(a, b + 1);

	sz = na + nb + 2;
	str = (char *) malloc(sz);
	CHECK(str != NULL);
	strcpy(str, a);
	strcat(str, "/");
	strcat(str, b);
	return str;
}

static char *dir_path(struct dir_info *parent, const char *name)
{
	char *parent_path;
	char *path;

	if (!parent)
		return cat_paths(tests_file_system_mount_dir, name);
	parent_path = dir_path(parent->parent, parent->name);
	path = cat_paths(parent_path, name);
	free(parent_path);
	return path;
}

static void open_file_add(struct fd_info *fdi)
{
	struct open_file_info *ofi;
	size_t sz;

	sz = sizeof(struct open_file_info);
	ofi = (struct open_file_info *) malloc(sz);
	CHECK(ofi != NULL);
	memset(ofi, 0, sz);
	ofi->next = open_files;
	ofi->fdi = fdi;
	open_files = ofi;
	open_files_count += 1;
}

static void open_file_remove(struct fd_info *fdi)
{
	struct open_file_info *ofi;
	struct open_file_info **prev;

	prev = &open_files;
	for (ofi = open_files; ofi; ofi = ofi->next) {
		if (ofi->fdi == fdi) {
			*prev = ofi->next;
			free(ofi);
			open_files_count -= 1;
			return;
		}
		prev = &ofi->next;
	}
	CHECK(0); /* We are trying to remove something that is not there */
}

static struct fd_info *add_fd(struct file_info *file, int fd)
{
	struct fd_info *fdi;
	size_t sz;

	sz = sizeof(struct fd_info);
	fdi = (struct fd_info *) malloc(sz);
	CHECK(fdi != NULL);
	memset(fdi, 0, sz);
	fdi->next = file->fds;
	fdi->file = file;
	fdi->fd = fd;
	file->fds = fdi;
	open_file_add(fdi);
	return fdi;
}

static void add_dir_entry(struct dir_info *parent, char type, const char *name,
			  void *target)
{
	struct dir_entry_info *entry;
	size_t sz;

	sz = sizeof(struct dir_entry_info);
	entry = (struct dir_entry_info *) malloc(sz);
	CHECK(entry != NULL);
	memset(entry, 0, sz);

	entry->type = type;
	entry->name = copy_string(name);
	entry->parent = parent;

	entry->next = parent->first;
	if (parent->first)
		parent->first->prev = entry;
	parent->first = entry;
	parent->number_of_entries += 1;

	if (entry->type == 'f') {
		struct file_info *file = target;

		entry->entry.file = file;
		entry->next_link = file->links;
		if (file->links)
			file->links->prev_link = entry;
		file->links = entry;
		file->link_count += 1;
	} else if (entry->type == 'd') {
		struct dir_info *dir = target;

		entry->entry.dir = dir;
		dir->entry = entry;
		dir->name = copy_string(name);
		dir->parent = parent;
	} else if (entry->type == 's') {
		struct symlink_info *symlink = target;

		entry->entry.symlink = symlink;
		symlink->entry = entry;
	}
}

static void remove_dir_entry(struct dir_entry_info *entry)
{
	entry->parent->number_of_entries -= 1;
	if (entry->parent->first == entry)
		entry->parent->first = entry->next;
	if (entry->prev)
		entry->prev->next = entry->next;
	if (entry->next)
		entry->next->prev = entry->prev;

	if (entry->type == 'f') {
		struct file_info *file = entry->entry.file;

		if (entry->prev_link)
			entry->prev_link->next_link = entry->next_link;
		if (entry->next_link)
			entry->next_link->prev_link = entry->prev_link;
		if (file->links == entry)
			file->links = entry->next_link;
		file->link_count -= 1;
		if (file->link_count == 0)
			file->deleted = 1;
	}

	free(entry->name);
	free(entry);
}

static struct dir_info *dir_new(struct dir_info *parent, const char *name)
{
	struct dir_info *dir;
	size_t sz;
	char *path;

	path = dir_path(parent, name);
	if (mkdir(path, 0777) == -1) {
		CHECK(errno == ENOSPC);
		full = 1;
		free(path);
		return NULL;
	}
	free(path);

	sz = sizeof(struct dir_info);
	dir = (struct dir_info *) malloc(sz);
	CHECK(dir != NULL);
	memset(dir, 0, sz);
	dir->name = copy_string(name);
	dir->parent = parent;
	if (parent)
		add_dir_entry(parent, 'd', name, dir);
	return dir;
}

static void file_delete(struct file_info *file);
static void file_unlink(struct dir_entry_info *entry);
static void symlink_remove(struct symlink_info *symlink);

static void dir_remove(struct dir_info *dir)
{
	char *path;

	/* Remove directory contents */
	while (dir->first) {
		struct dir_entry_info *entry;

		entry = dir->first;
		if (entry->type == 'd')
			dir_remove(entry->entry.dir);
		else if (entry->type == 'f')
			file_unlink(entry);
		else if (entry->type == 's')
			symlink_remove(entry->entry.symlink);
		else
			CHECK(0); /* Invalid struct dir_entry_info */
	}
	/* Remove entry from parent directory */
	remove_dir_entry(dir->entry);
	/* Remove directory itself */
	path = dir_path(dir->parent, dir->name);
	CHECK(rmdir(path) != -1);
	free(dir);
}

static struct file_info *file_new(struct dir_info *parent, const char *name)
{
	struct file_info *file = NULL;
	char *path;
	mode_t mode;
	int fd;
	size_t sz;

	CHECK(parent != NULL);

	path = dir_path(parent, name);
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH;
	fd = open(path, O_CREAT | O_EXCL | O_RDWR, mode);
	if (fd == -1) {
		CHECK(errno == ENOSPC);
		free(path);
		full = 1;
		return NULL;
	}
	free(path);

	sz = sizeof(struct file_info);
	file = (struct file_info *) malloc(sz);
	CHECK(file != NULL);
	memset(file, 0, sz);
	file->name = copy_string(name);

	add_dir_entry(parent, 'f', name, file);

	add_fd(file, fd);

	return file;
}

static void link_new(struct dir_info *parent, const char *name,
		     struct file_info *file)
{
	struct dir_entry_info *entry;
	char *path, *target;
	int ret;

	if (!file)
		return;
	entry = file->links;
	if (!entry)
		return;
	path = dir_path(parent, name);
	target = dir_path(entry->parent, entry->name);
	ret = link(target, path);
	if (ret == -1) {
		CHECK(errno == ENOSPC);
		free(target);
		free(path);
		full = 1;
		return;
	}
	free(target);
	free(path);

	add_dir_entry(parent, 'f', name, file);
}

static void file_close(struct fd_info *fdi);

static void file_close_all(struct file_info *file)
{
	struct fd_info *fdi = file->fds;

	while (fdi) {
		struct fd_info *next = fdi->next;

		file_close(fdi);
		fdi = next;
	}
}

static void file_unlink(struct dir_entry_info *entry)
{
	struct file_info *file = entry->entry.file;
	char *path;

	path = dir_path(entry->parent, entry->name);

	/* Remove file entry from parent directory */
	remove_dir_entry(entry);

	/* Unlink the file */
	CHECK(unlink(path) != -1);
	free(path);

	/* Free struct file_info if file is not open and not linked */
	if (!file->fds && !file->links) {
		struct write_info *w, *next;

		free(file->name);
		w = file->writes;
		while (w) {
			next = w->next;
			free(w);
			w = next;
		}
		free(file);
	} else if (!file->links)
		file->deleted = 1;
}

static struct dir_entry_info *pick_entry(struct file_info *file)
{
	struct dir_entry_info *entry;
	size_t r;

	if (!file->link_count)
		return NULL;
	r = tests_random_no(file->link_count);
	entry = file->links;
	while (entry && r--)
		entry = entry->next_link;
	return entry;
}

static void file_unlink_file(struct file_info *file)
{
	struct dir_entry_info *entry;

	entry = pick_entry(file);
	if (!entry)
		return;
	file_unlink(entry);
}

static void file_delete(struct file_info *file)
{
	struct dir_entry_info *entry = file->links;

	file_close_all(file);
	while (entry) {
		struct dir_entry_info *next = entry->next_link;

		file_unlink(entry);
		entry = next;
	}
}

static void file_info_display(struct file_info *file)
{
	struct dir_entry_info *entry;
	struct write_info *w;
	unsigned wcnt;

	fprintf(stderr, "File Info:\n");
	fprintf(stderr, "    Original name: %s\n", file->name);
	fprintf(stderr, "    Link count: %d\n", file->link_count);
	fprintf(stderr, "    Links:\n");
	entry = file->links;
	while (entry) {
		fprintf(stderr, "      Name: %s\n", entry->name);
		fprintf(stderr, "      Directory: %s\n", entry->parent->name);
		entry = entry->next_link;
	}
	fprintf(stderr, "    Length: %u\n", (unsigned) file->length);
	fprintf(stderr, "    File was open: %s\n",
		(file->fds == NULL) ? "false" : "true");
	fprintf(stderr, "    File was deleted: %s\n",
		(file->deleted == 0) ? "false" : "true");
	fprintf(stderr, "    File was out of space: %s\n",
		(file->no_space_error == 0) ? "false" : "true");
	fprintf(stderr, "    File Data:\n");
	wcnt = 0;
	w = file->writes;
	while (w) {
		fprintf(stderr, "        Offset: %u  Size: %u  Seed: %u"
				"  R.Off: %u\n",
				(unsigned) w->offset,
				(unsigned) w->size,
				(unsigned) w->random_seed,
				(unsigned) w->random_offset);
		wcnt += 1;
		w = w->next;
	}
	fprintf(stderr, "    %u writes\n", wcnt);
	fprintf(stderr, "    ============================================\n");
	fprintf(stderr, "    Write Info:\n");
	wcnt = 0;
	w = file->raw_writes;
	while (w) {
		if (w->trunc)
			fprintf(stderr, "        Trunc from %u to %u\n",
					(unsigned) w->offset,
					(unsigned) w->random_offset);
		else
			fprintf(stderr, "        Offset: %u  Size: %u  Seed: %u"
					"  R.Off: %u\n",
					(unsigned) w->offset,
					(unsigned) w->size,
					(unsigned) w->random_seed,
					(unsigned) w->random_offset);
		wcnt += 1;
		w = w->next;
	}
	fprintf(stderr, "    %u writes or truncations\n", wcnt);
	fprintf(stderr, "    ============================================\n");
}

static struct fd_info *file_open(struct file_info *file)
{
	int fd, flags = O_RDWR;
	char *path;

	path = dir_path(file->links->parent, file->links->name);
	if (tests_random_no(100) == 1)
		flags |= O_SYNC;
	fd = open(path, flags);
	CHECK(fd != -1);
	free(path);
	return add_fd(file, fd);
}

#define BUFFER_SIZE 32768

static size_t file_write_data(	struct file_info *file,
				int fd,
				off_t offset,
				size_t size,
				unsigned seed)
{
	size_t remains, actual, block;
	ssize_t written;
	char buf[BUFFER_SIZE];

	srand(seed);
	CHECK(lseek(fd, offset, SEEK_SET) != (off_t) -1);
	remains = size;
	actual = 0;
	written = BUFFER_SIZE;
	while (remains) {
		/* Fill up buffer with random data */
		if (written < BUFFER_SIZE) {
			memmove(buf, buf + written, BUFFER_SIZE - written);
			written = BUFFER_SIZE - written;
		} else
			written = 0;
		for (; written < BUFFER_SIZE; ++written)
			buf[written] = rand();
		/* Write a block of data */
		if (remains > BUFFER_SIZE)
			block = BUFFER_SIZE;
		else
			block = remains;
		written = write(fd, buf, block);
		if (written < 0) {
			CHECK(errno == ENOSPC); /* File system full */
			full = 1;
			file->no_space_error = 1;
			break;
		}
		remains -= written;
		actual += written;
	}
	return actual;
}

static void file_write_info(struct file_info *file,
			off_t offset,
			size_t size,
			unsigned seed)
{
	struct write_info *new_write, *w, **prev, *tmp;
	int inserted;
	size_t sz;
	off_t end, chg;

	/* Create struct write_info */
	sz = sizeof(struct write_info);
	new_write = (struct write_info *) malloc(sz);
	CHECK(new_write != NULL);
	memset(new_write, 0, sz);
	new_write->offset = offset;
	new_write->size = size;
	new_write->random_seed = seed;

	w = (struct write_info *) malloc(sz);
	CHECK(w != NULL);
	memset(w, 0, sz);
	w->next = file->raw_writes;
	w->offset = offset;
	w->size = size;
	w->random_seed = seed;
	file->raw_writes = w;

	/* Insert it into file->writes */
	inserted = 0;
	end = offset + size;
	w = file->writes;
	prev = &file->writes;
	while (w) {
		if (w->offset >= end) {
			/* w comes after new_write, so insert before it */
			new_write->next = w;
			*prev = new_write;
			inserted = 1;
			break;
		}
		/* w does not come after new_write */
		if (w->offset + w->size > offset) {
			/* w overlaps new_write */
			if (w->offset < offset) {
				/* w begins before new_write begins */
				if (w->offset + w->size <= end)
					/* w ends before new_write ends */
					w->size = offset - w->offset;
				else {
					/* w ends after new_write ends */
					/* Split w */
					tmp = (struct write_info *) malloc(sz);
					CHECK(tmp != NULL);
					*tmp = *w;
					chg = end - tmp->offset;
					tmp->offset += chg;
					tmp->random_offset += chg;
					tmp->size -= chg;
					w->size = offset - w->offset;
					/* Insert new struct write_info */
					w->next = new_write;
					new_write->next = tmp;
					inserted = 1;
					break;
				}
			} else {
				/* w begins after new_write begins */
				if (w->offset + w->size <= end) {
					/* w is completely overlapped,
					   so remove it */
					*prev = w->next;
					tmp = w;
					w = w->next;
					free(tmp);
					continue;
				}
				/* w ends after new_write ends */
				chg = end - w->offset;
				w->offset += chg;
				w->random_offset += chg;
				w->size -= chg;
				continue;
			}
		}
		prev = &w->next;
		w = w->next;
	}
	if (!inserted)
		*prev = new_write;
	/* Update file length */
	if (end > file->length)
		file->length = end;
}

/* Randomly select offset and and size to write in a file */
static void get_offset_and_size(struct file_info *file,
				off_t *offset,
				size_t *size)
{
	size_t r, n;

	r = tests_random_no(100);
	if (r == 0 && grow)
		/* 1 time in 100, when growing, write off the end of the file */
		*offset = file->length + tests_random_no(10000000);
	else if (r < 4)
		/* 3 (or 4) times in 100, write at the beginning of file */
		*offset = 0;
	else if (r < 52 || !grow)
		/* 48 times in 100, write into the file */
		*offset = tests_random_no(file->length);
	else
		/* 48 times in 100, write at the end of the  file */
		*offset = file->length;
	/* Distribute the size logarithmically */
	if (tests_random_no(1000) == 0)
		r = tests_random_no(log10_initial_free_space + 2);
	else
		r = tests_random_no(log10_initial_free_space);
	n = 1;
	while (r--)
		n *= 10;
	*size = tests_random_no(n);
	if (!grow && *offset + *size > file->length)
		*size = file->length - *offset;
	if (*size == 0)
		*size = 1;
}

static void file_truncate_info(struct file_info *file, size_t new_length);

static int file_ftruncate(struct file_info *file, int fd, off_t new_length)
{
	if (ftruncate(fd, new_length) == -1) {
		CHECK(errno = ENOSPC);
		file->no_space_error = 1;
		/* Delete errored files */
		if (!check_nospc_files)
			file_delete(file);
		return 0;
	}
	return 1;
}

static void file_mmap_write(struct file_info *file)
{
	size_t write_cnt = 0, r, i, len, size;
	struct write_info *w = file->writes;
	void *addr;
	char *waddr;
	off_t offs, offset;
	unsigned seed;
	uint64_t free_space;
	int fd;
	char *path;

	if (!file->links)
		return;
	free_space = tests_get_free_space();
	if (!free_space)
		return;
	/* Randomly pick a written area of the file */
	if (!w)
		return;
	while (w) {
		write_cnt += 1;
		w = w->next;
	}
	r = tests_random_no(write_cnt);
	w = file->writes;
	for (i = 0; w && w->next && i < r; i++)
		w = w->next;

	offs = (w->offset / mem_page_size) * mem_page_size;
	len = w->size + (w->offset - offs);
	if (len > 1 << 24)
		len = 1 << 24;

	/* Open it */
	path = dir_path(file->links->parent, file->links->name);
	fd = open(path, O_RDWR);
	CHECK(fd != -1);
	free(path);

	/* mmap it */
	addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offs);
	CHECK(close(fd) != -1);
	CHECK(addr != MAP_FAILED);

	/* Randomly select a part of the mmapped area to write */
	size = tests_random_no(w->size);
	if (size > free_space)
		size = free_space;
	if (size == 0)
		size = 1;
	offset = w->offset + tests_random_no(w->size - size);

	/* Write it */
	seed = tests_random_no(10000000);
	srand(seed);
	waddr = addr + (offset - offs);
	for (i = 0; i < size; i++)
		waddr[i] = rand();

	/* Unmap it */
	CHECK(munmap(addr, len) != -1);

	/* Record what was written */
	file_write_info(file, offset, size, seed);
}

static void file_write(struct file_info *file, int fd)
{
	off_t offset;
	size_t size, actual;
	unsigned seed;
	int truncate = 0;

	if (can_mmap && !full && !file->deleted && tests_random_no(100) == 1) {
		file_mmap_write(file);
		return;
	}

	get_offset_and_size(file, &offset, &size);
	seed = tests_random_no(10000000);
	actual = file_write_data(file, fd, offset, size, seed);

	if (offset + actual <= file->length && shrink)
		/* 1 time in 100, when shrinking
		   truncate after the write */
		if (tests_random_no(100) == 0)
			truncate = 1;

	if (actual != 0)
		file_write_info(file, offset, actual, seed);

	/* Delete errored files */
	if (!check_nospc_files && file->no_space_error) {
		file_delete(file);
		return;
	}

	if (truncate) {
		size_t new_length = offset + actual;
		if (file_ftruncate(file, fd, new_length))
			file_truncate_info(file, new_length);
	}
}

static void file_write_file(struct file_info *file)
{
	int fd;
	char *path;

	path = dir_path(file->links->parent, file->links->name);
	fd = open(path, O_WRONLY);
	CHECK(fd != -1);
	file_write(file, fd);
	CHECK(close(fd) != -1);
	free(path);
}

static void file_truncate_info(struct file_info *file, size_t new_length)
{
	struct write_info *w, **prev, *tmp;
	size_t sz;

	/* Remove / truncate file->writes */
	w = file->writes;
	prev = &file->writes;
	while (w) {
		if (w->offset >= new_length) {
			/* w comes after eof, so remove it */
			*prev = w->next;
			tmp = w;
			w = w->next;
			free(tmp);
			continue;
		}
		if (w->offset + w->size > new_length)
			w->size = new_length - w->offset;
		prev = &w->next;
		w = w->next;
	}
	/* Add an entry in raw_writes for the truncation */
	sz = sizeof(struct write_info);
	w = (struct write_info *) malloc(sz);
	CHECK(w != NULL);
	memset(w, 0, sz);
	w->next = file->raw_writes;
	w->offset = file->length;
	w->random_offset = new_length; /* Abuse random_offset */
	w->trunc = 1;
	file->raw_writes = w;
	/* Update file length */
	file->length = new_length;
}

static void file_truncate(struct file_info *file, int fd)
{
	size_t new_length;

	new_length = tests_random_no(file->length);

	if (file_ftruncate(file, fd, new_length))
		file_truncate_info(file, new_length);
}

static void file_truncate_file(struct file_info *file)
{
	int fd;
	char *path;

	path = dir_path(file->links->parent, file->links->name);
	fd = open(path, O_WRONLY);
	CHECK(fd != -1);
	file_truncate(file, fd);
	CHECK(close(fd) != -1);
	free(path);
}

static void file_close(struct fd_info *fdi)
{
	struct file_info *file;
	struct fd_info *fdp;
	struct fd_info **prev;

	/* Close file */
	CHECK(close(fdi->fd) != -1);
	/* Remove struct fd_info */
	open_file_remove(fdi);
	file = fdi->file;
	prev = &file->fds;
	for (fdp = file->fds; fdp; fdp = fdp->next) {
		if (fdp == fdi) {
			*prev = fdi->next;
			free(fdi);
			if (file->deleted && !file->fds) {
				/* Closing deleted file */
				struct write_info *w, *next;

				w = file->writes;
				while (w) {
					next = w->next;
					free(w);
					w = next;
				}
				free(file->name);
				free(file);
			}
			return;
		}
		prev = &fdp->next;
	}
	CHECK(0); /* Didn't find struct fd_info */
}

static void file_rewrite_data(int fd, struct write_info *w, char *buf)
{
	size_t remains, block;
	ssize_t written;
	off_t r;

	srand(w->random_seed);
	for (r = 0; r < w->random_offset; ++r)
		rand();
	CHECK(lseek(fd, w->offset, SEEK_SET) != (off_t) -1);
	remains = w->size;
	written = BUFFER_SIZE;
	while (remains) {
		/* Fill up buffer with random data */
		if (written < BUFFER_SIZE)
			memmove(buf, buf + written, BUFFER_SIZE - written);
		else
			written = 0;
		for (; written < BUFFER_SIZE; ++written)
			buf[written] = rand();
		/* Write a block of data */
		if (remains > BUFFER_SIZE)
			block = BUFFER_SIZE;
		else
			block = remains;
		written = write(fd, buf, block);
		CHECK(written == block);
		remains -= written;
	}
}

static void save_file(int fd, struct file_info *file)
{
	int w_fd;
	struct write_info *w;
	char buf[BUFFER_SIZE];
	char name[256];

	/* Open file to save contents to */
	strcpy(name, "/tmp/");
	strcat(name, file->name);
	strcat(name, ".integ.sav.read");
	fprintf(stderr, "Saving %s\n", name);
	w_fd = open(name, O_CREAT | O_WRONLY, 0777);
	CHECK(w_fd != -1);

	/* Start at the beginning */
	CHECK(lseek(fd, 0, SEEK_SET) != (off_t) -1);

	for (;;) {
		ssize_t r = read(fd, buf, BUFFER_SIZE);
		CHECK(r != -1);
		if (!r)
			break;
		CHECK(write(w_fd, buf, r) == r);
	}
	CHECK(close(w_fd) != -1);

	/* Open file to save contents to */
	strcpy(name, "/tmp/");
	strcat(name, file->name);
	strcat(name, ".integ.sav.written");
	fprintf(stderr, "Saving %s\n", name);
	w_fd = open(name, O_CREAT | O_WRONLY, 0777);
	CHECK(w_fd != -1);

	for (w = file->writes; w; w = w->next)
		file_rewrite_data(w_fd, w, buf);

	CHECK(close(w_fd) != -1);
}

static void file_check_hole(	struct file_info *file,
				int fd, off_t offset,
				size_t size)
{
	size_t remains, block, i;
	char buf[BUFFER_SIZE];

	CHECK(lseek(fd, offset, SEEK_SET) != (off_t) -1);
	remains = size;
	while (remains) {
		if (remains > BUFFER_SIZE)
			block = BUFFER_SIZE;
		else
			block = remains;
		CHECK(read(fd, buf, block) == block);
		for (i = 0; i < block; ++i) {
			if (buf[i] != 0) {
				fprintf(stderr, "file_check_hole failed at %u "
					"checking hole at %u size %u\n",
					(unsigned) (size - remains + i),
					(unsigned) offset,
					(unsigned) size);
				file_info_display(file);
				save_file(fd, file);
			}
			CHECK(buf[i] == 0);
		}
		remains -= block;
	}
}

static void file_check_data(	struct file_info *file,
				int fd,
				struct write_info *w)
{
	size_t remains, block, i;
	off_t r;
	char buf[BUFFER_SIZE];

	srand(w->random_seed);
	for (r = 0; r < w->random_offset; ++r)
		rand();
	CHECK(lseek(fd, w->offset, SEEK_SET) != (off_t) -1);
	remains = w->size;
	while (remains) {
		if (remains > BUFFER_SIZE)
			block = BUFFER_SIZE;
		else
			block = remains;
		CHECK(read(fd, buf, block) == block);
		for (i = 0; i < block; ++i) {
			char c = (char) rand();
			if (buf[i] != c) {
				fprintf(stderr, "file_check_data failed at %u "
					"checking data at %u size %u\n",
					(unsigned) (w->size - remains + i),
					(unsigned) w->offset,
					(unsigned) w->size);
				file_info_display(file);
				save_file(fd, file);
			}
			CHECK(buf[i] == c);
		}
		remains -= block;
	}
}

static void file_check(struct file_info *file, int fd)
{
	int open_and_close = 0, link_count = 0;
	char *path = NULL;
	off_t pos;
	struct write_info *w;
	struct dir_entry_info *entry;
	struct stat st;

	/* Do not check files that have errored */
	if (!check_nospc_files && file->no_space_error)
		return;
	/* Do not check the same file twice */
	if (file->check_run_no == check_run_no)
		return;
	file->check_run_no = check_run_no;
	if (fd == -1)
		open_and_close = 1;
	if (open_and_close) {
		/* Open file */
		path = dir_path(file->links->parent, file->links->name);
		fd = open(path, O_RDONLY);
		CHECK(fd != -1);
	}
	/* Check length */
	pos = lseek(fd, 0, SEEK_END);
	if (pos != file->length) {
		fprintf(stderr, "file_check failed checking length "
			"expected %u actual %u\n",
			(unsigned) file->length,
			(unsigned) pos);
		file_info_display(file);
		save_file(fd, file);
	}
	CHECK(pos == file->length);
	/* Check each write */
	pos = 0;
	for (w = file->writes; w; w = w->next) {
		if (w->offset > pos)
			file_check_hole(file, fd, pos, w->offset - pos);
		file_check_data(file, fd, w);
		pos = w->offset + w->size;
	}
	if (file->length > pos)
		file_check_hole(file, fd, pos, file->length - pos);
	CHECK(fstat(fd, &st) != -1);
	CHECK(file->link_count == st.st_nlink);
	if (open_and_close) {
		CHECK(close(fd) != -1);
		free(path);
	}
	entry = file->links;
	while (entry) {
		link_count += 1;
		entry = entry->next_link;
	}
	CHECK(link_count == file->link_count);
}

static char *symlink_path(const char *path, const char *target_pathname)
{
	char *p;
	size_t len, totlen, tarlen;

	if (target_pathname[0] == '/')
		return copy_string(target_pathname);
	p = strrchr(path, '/');
	len = p - path;
	len += 1;
	tarlen = strlen(target_pathname);
	totlen = len + tarlen + 1;
	p = malloc(totlen);
	CHECK(p != NULL);
	strncpy(p, path, len);
	p[len] = '\0';
	strcat(p, target_pathname);
	return p;
}

void symlink_check(const struct symlink_info *symlink)
{
	char *path, buf[8192], *target;
	struct stat st1, st2;
	ssize_t len;
	int ret1, ret2;

	path = dir_path(symlink->entry->parent, symlink->entry->name);
	CHECK(lstat(path, &st1) != -1);
	CHECK(S_ISLNK(st1.st_mode));
	CHECK(st1.st_nlink == 1);
	len = readlink(path, buf, 8192);
	CHECK(len > 0 && len < 8192);
	buf[len] = '\0';
	CHECK(strlen(symlink->target_pathname) == len);
	CHECK(strncmp(symlink->target_pathname, buf, len) == 0);
	/* Check symlink points where it should */
	ret1 = stat(path, &st1);
	target = symlink_path(path, symlink->target_pathname);
	ret2 = stat(target, &st2);
	CHECK(ret1 == ret2);
	if (ret1 != -1) {
		CHECK(st1.st_dev == st2.st_dev);
		CHECK(st1.st_ino == st2.st_ino);
	}
	free(target);
	free(path);
}

static int search_comp(const void *pa, const void *pb)
{
	const struct dirent *a = (const struct dirent *) pa;
	const struct dir_entry_info *b = * (const struct dir_entry_info **) pb;
	return strcmp(a->d_name, b->name);
}

static void dir_entry_check(struct dir_entry_info **entry_array,
			size_t number_of_entries,
			struct dirent *ent)
{
	struct dir_entry_info **found;
	struct dir_entry_info *entry;
	size_t sz;

	sz = sizeof(struct dir_entry_info *);
	found = bsearch(ent, entry_array, number_of_entries, sz, search_comp);
	CHECK(found != NULL);
	entry = *found;
	CHECK(!entry->checked);
	entry->checked = 1;
}

static int sort_comp(const void *pa, const void *pb)
{
	const struct dir_entry_info *a = * (const struct dir_entry_info **) pa;
	const struct dir_entry_info *b = * (const struct dir_entry_info **) pb;
	return strcmp(a->name, b->name);
}

static void dir_check(struct dir_info *dir)
{
	struct dir_entry_info **entry_array, **p;
	size_t sz, n;
	struct dir_entry_info *entry;
	DIR *d;
	struct dirent *ent;
	unsigned checked = 0;
	char *path;
	int link_count = 2; /* Parent and dot */
	struct stat st;

	/* Create an array of entries */
	sz = sizeof(struct dir_entry_info *);
	n = dir->number_of_entries;
	entry_array = (struct dir_entry_info **) malloc(sz * n);
	CHECK(entry_array != NULL);

	entry = dir->first;
	p = entry_array;
	while (entry) {
		*p++ = entry;
		entry->checked = 0;
		entry = entry->next;
	}

	/* Sort it by name */
	qsort(entry_array, n, sz, sort_comp);

	/* Go through directory on file system checking entries match */
	path = dir_path(dir->parent, dir->name);
	d = opendir(path);
	CHECK(d != NULL);
	for (;;) {
		errno = 0;
		ent = readdir(d);
		if (ent) {
			if (strcmp(".",ent->d_name) != 0 &&
					strcmp("..",ent->d_name) != 0) {
				dir_entry_check(entry_array, n, ent);
				checked += 1;
			}
		} else {
			CHECK(errno == 0);
			break;
		}
	}
	CHECK(closedir(d) != -1);
	CHECK(checked == dir->number_of_entries);

	/* Now check each entry */
	entry = dir->first;
	while (entry) {
		if (entry->type == 'd') {
			dir_check(entry->entry.dir);
			link_count += 1; /* <subdir>/.. */
		} else if (entry->type == 'f')
			file_check(entry->entry.file, -1);
		else if (entry->type == 's')
			symlink_check(entry->entry.symlink);
		else
			CHECK(0);
		entry = entry->next;
	}

	CHECK(stat(path, &st) != -1);
	CHECK(link_count == st.st_nlink);

	free(entry_array);
	free(path);
}

static void check_deleted_files(void)
{
	struct open_file_info *ofi;

	for (ofi = open_files; ofi; ofi = ofi->next)
		if (ofi->fdi->file->deleted)
			file_check(ofi->fdi->file, ofi->fdi->fd);
}

static void close_open_files(void)
{
	struct open_file_info *ofi;

	for (ofi = open_files; ofi; ofi = open_files)
		file_close(ofi->fdi);
}

static char *make_name(struct dir_info *dir)
{
	static char name[256];
	struct dir_entry_info *entry;
	int found;

	do {
		found = 0;
		if (tests_random_no(5) == 1) {
			int i, n = tests_random_no(tests_max_fname_len) + 1;

			CHECK(n > 0 && n < 256);
			for (i = 0; i < n; i++)
				name[i] = 'a' + tests_random_no(26);
			name[i] = '\0';
		} else
			sprintf(name, "%u", (unsigned) tests_random_no(1000000));
		for (entry = dir->first; entry; entry = entry->next) {
			if (strcmp(entry->name, name) == 0) {
				found = 1;
				break;
			}
		}
	} while (found);
	return name;
}

static struct file_info *pick_file(void)
{
	struct dir_info *dir = top_dir;

	for (;;) {
		struct dir_entry_info *entry;
		size_t r;

		r = tests_random_no(dir->number_of_entries);
		entry = dir->first;
		while (entry && r) {
			entry = entry->next;
			--r;
		}
		for (;;) {
			if (!entry)
				return NULL;
			if (entry->type == 'f')
				return entry->entry.file;
			if (entry->type == 'd')
				if (entry->entry.dir->number_of_entries != 0)
					break;
			entry = entry->next;
		}
		dir = entry->entry.dir;
	}
}

static struct dir_info *pick_dir(void)
{
	struct dir_info *dir = top_dir;

	if (tests_random_no(40) >= 30)
		return dir;
	for (;;) {
		struct dir_entry_info *entry;
		size_t r;

		r = tests_random_no(dir->number_of_entries);
		entry = dir->first;
		while (entry && r) {
			entry = entry->next;
			--r;
		}
		for (;;) {
			if (!entry)
				break;
			if (entry->type == 'd')
				break;
			entry = entry->next;
		}
		if (!entry) {
			entry = dir->first;
			for (;;) {
				if (!entry)
					break;
				if (entry->type == 'd')
					break;
				entry = entry->next;
			}
		}
		if (!entry)
			return dir;
		dir = entry->entry.dir;
		if (tests_random_no(40) >= 30)
			return dir;
	}
}

static char *pick_rename_name(struct dir_info **parent,
			      struct dir_entry_info **rename_entry, int isdir)
{
	struct dir_info *dir = pick_dir();
	struct dir_entry_info *entry;
	size_t r;

	*parent = dir;
	*rename_entry = NULL;

	if (grow || tests_random_no(20) < 10)
		return copy_string(make_name(dir));

	r = tests_random_no(dir->number_of_entries);
	entry = dir->first;
	while (entry && r) {
		entry = entry->next;
		--r;
	}
	if (!entry)
		entry = dir->first;
	if (!entry ||
	    (entry->type == 'd' && entry->entry.dir->number_of_entries != 0))
		return copy_string(make_name(dir));

	if ((isdir && entry->type != 'd') ||
	    (!isdir && entry->type == 'd'))
		return copy_string(make_name(dir));

	*rename_entry = entry;
	return copy_string(entry->name);
}

static void rename_entry(struct dir_entry_info *entry)
{
	struct dir_entry_info *rename_entry = NULL;
	struct dir_info *parent;
	char *path, *to, *name;
	int ret, isdir, retry;

	if (!entry->parent)
		return;

	for (retry = 0; retry < 3; retry++) {
		path = dir_path(entry->parent, entry->name);
		isdir = entry->type == 'd' ? 1 : 0;
		name = pick_rename_name(&parent, &rename_entry, isdir);
		to = dir_path(parent, name);
		/*
		 * Check we are not trying to move a directory to a subdirectory
		 * of itself.
		 */
		if (isdir) {
			struct dir_info *p;

			for (p = parent; p; p = p->parent)
				if (p == entry->entry.dir)
					break;
			if (p == entry->entry.dir) {
				free(path);
				free(name);
				free(to);
				path = NULL;
				continue;
			}
		}
		break;
	}

	if (!path)
		return;

	ret = rename(path, to);
	if (ret == -1) {
		if (errno == ENOSPC)
			full = 1;
		CHECK(errno == ENOSPC || errno == EBUSY);
		free(path);
		free(name);
		free(to);
		return;
	}

	free(path);
	free(to);

	if (rename_entry && rename_entry->type == entry->type &&
	    rename_entry->entry.target == entry->entry.target) {
		free(name);
		return;
	}

	add_dir_entry(parent, entry->type, name, entry->entry.target);
	if (rename_entry)
		remove_dir_entry(rename_entry);
	remove_dir_entry(entry);
	free(name);
}

static size_t str_count(const char *s, char c)
{
	size_t count = 0;
	char cc;

	while ((cc = *s++) != '\0')
		if (cc == c)
			count += 1;
	return count;
}

static char *relative_path(const char *path1, const char *path2)
{
	const char *p1, *p2;
	char *rel;
	size_t up, len, len2, i;

	p1 = path1;
	p2 = path2;
	while (*p1 == *p2 && *p1) {
		p1 += 1;
		p2 += 1;
	}
	len2 = strlen(p2);
	up = str_count(p1, '/');
	if (up == 0 && len2 != 0)
		return copy_string(p2);
	if (up == 0 && len2 == 0) {
		p2 = strrchr(path2, '/');
		return copy_string(p2);
	}
	if (up == 1 && len2 == 0)
		return copy_string(".");
	if (len2 == 0)
		up -= 1;
	len = up * 3 + len2 + 1;
	rel = malloc(len);
	CHECK(rel != NULL);
	rel[0] = '\0';
	if (up) {
		strcat(rel, "..");
		for (i = 1; i < up; i++)
			strcat(rel, "/..");
		if (len2)
			strcat(rel, "/");
	}
	if (len2)
		strcat(rel, p2);
	return rel;
}

static char *pick_symlink_target(const char *symlink_path)
{
	struct dir_info *dir;
	struct dir_entry_info *entry;
	size_t r;
	char *path, *rel_path;

	dir = pick_dir();

	if (tests_random_no(100) < 10)
		return dir_path(dir, make_name(dir));

	r = tests_random_no(dir->number_of_entries);
	entry = dir->first;
	while (entry && r) {
		entry = entry->next;
		--r;
	}
	if (!entry)
		entry = dir->first;
	if (!entry)
		return dir_path(dir, make_name(dir));
	path = dir_path(dir, entry->name);
	if (tests_random_no(20) < 10)
		return path;
	rel_path = relative_path(symlink_path, path);
	free(path);
	return rel_path;
}

static void symlink_new(struct dir_info *dir, const char *name_)
{
	struct symlink_info *s;
	char *path, *target, *name = copy_string(name_);
	size_t sz;

	path = dir_path(dir, name);
	target = pick_symlink_target(path);
	if (symlink(target, path) == -1) {
		CHECK(errno == ENOSPC || errno == ENAMETOOLONG);
		if (errno == ENOSPC)
			full = 1;
		free(target);
		free(path);
		free(name);
		return;
	}
	free(path);

	sz = sizeof(struct symlink_info);
	s = malloc(sz);
	CHECK(s != NULL);
	memset(s, 0, sz);
	add_dir_entry(dir, 's', name, s);
	s->target_pathname = target;
	free(name);
}

static void symlink_remove(struct symlink_info *symlink)
{
	char *path;

	path = dir_path(symlink->entry->parent, symlink->entry->name);

	remove_dir_entry(symlink->entry);

	CHECK(unlink(path) != -1);
	free(path);
}

static void operate_on_dir(struct dir_info *dir);
static void operate_on_file(struct file_info *file);

/* Randomly select something to do with a directory entry */
static void operate_on_entry(struct dir_entry_info *entry)
{
	/* 1 time in 1000 rename */
	if (tests_random_no(1000) == 0) {
		rename_entry(entry);
		return;
	}
	if (entry->type == 's') {
		symlink_check(entry->entry.symlink);
		/* If shrinking, 1 time in 50, remove a symlink */
		if (shrink && tests_random_no(50) == 0)
			symlink_remove(entry->entry.symlink);
		return;
	}
	if (entry->type == 'd') {
		/* If shrinking, 1 time in 50, remove a directory */
		if (shrink && tests_random_no(50) == 0) {
			dir_remove(entry->entry.dir);
			return;
		}
		operate_on_dir(entry->entry.dir);
	}
	if (entry->type == 'f') {
		/* If shrinking, 1 time in 10, remove a file */
		if (shrink && tests_random_no(10) == 0) {
			file_delete(entry->entry.file);
			return;
		}
		/* If not growing, 1 time in 10, unlink a file with links > 1 */
		if (!grow && entry->entry.file->link_count > 1 &&
		    tests_random_no(10) == 0) {
			file_unlink_file(entry->entry.file);
			return;
		}
		operate_on_file(entry->entry.file);
	}
}

/* Randomly select something to do with a directory */
static void operate_on_dir(struct dir_info *dir)
{
	size_t r;
	struct dir_entry_info *entry;
	struct file_info *file;

	r = tests_random_no(14);
	if (r == 0 && grow)
		/* When growing, 1 time in 14 create a file */
		file_new(dir, make_name(dir));
	else if (r == 1 && grow)
		/* When growing, 1 time in 14 create a directory */
		dir_new(dir, make_name(dir));
	else if (r == 2 && grow && (file = pick_file()) != NULL)
		/* When growing, 1 time in 14 create a hard link */
		link_new(dir, make_name(dir), file);
	else if (r == 3 && grow && tests_random_no(5) == 0)
		/* When growing, 1 time in 70 create a symbolic link */
		symlink_new(dir, make_name(dir));
	else {
		/* Otherwise randomly select an entry to operate on */
		r = tests_random_no(dir->number_of_entries);
		entry = dir->first;
		while (entry && r) {
			entry = entry->next;
			--r;
		}
		if (entry)
			operate_on_entry(entry);
	}
}

/* Randomly select something to do with a file */
static void operate_on_file(struct file_info *file)
{
	/* Try to keep at least 10 files open */
	if (open_files_count < 10) {
		file_open(file);
		return;
	}
	/* Try to keep about 20 files open */
	if (open_files_count < 20 && tests_random_no(2) == 0) {
		file_open(file);
		return;
	}
	/* Try to keep up to 40 files open */
	if (open_files_count < 40 && tests_random_no(20) == 0) {
		file_open(file);
		return;
	}
	/* Occasionly truncate */
	if (shrink && tests_random_no(100) == 0) {
		file_truncate_file(file);
		return;
	}
	/* Mostly just write */
	file_write_file(file);
	/* Once in a while check it too */
	if (tests_random_no(100) == 1) {
		int fd = -2;

		if (file->links)
			fd = -1;
		else if (file->fds)
			fd = file->fds->fd;
		if (fd != -2) {
			check_run_no += 1;
			file_check(file, fd);
		}
	}
}

/* Randomly select something to do with an open file */
static void operate_on_open_file(struct fd_info *fdi)
{
	size_t r;

	r = tests_random_no(1000);
	if (shrink && r < 5)
		file_truncate(fdi->file, fdi->fd);
	else if (r < 21)
		file_close(fdi);
	else if (shrink && r < 121 && !fdi->file->deleted)
		file_delete(fdi->file);
	else {
		file_write(fdi->file, fdi->fd);
		if (r >= 999) {
			if (tests_random_no(100) >= 50)
				CHECK(fsync(fdi->fd) != -1);
			else
				CHECK(fdatasync(fdi->fd) != -1);
		}
	}
}

/* Select an open file at random */
static void operate_on_an_open_file(void)
{
	size_t r;
	struct open_file_info *ofi;

	/* When shrinking, close all open files 1 time in 128 */
	if (shrink) {
		static int x = 0;

		x += 1;
		x &= 127;
		if (x == 0) {
			close_open_files();
			return;
		}
	}
	/* Close any open files that have errored */
	if (!check_nospc_files) {
		ofi = open_files;
		while (ofi) {
			if (ofi->fdi->file->no_space_error) {
				struct fd_info *fdi;

				fdi = ofi->fdi;
				ofi = ofi->next;
				file_close(fdi);
			} else
				ofi = ofi->next;
		}
	}
	r = tests_random_no(open_files_count);
	for (ofi = open_files; ofi; ofi = ofi->next, --r)
		if (!r) {
			operate_on_open_file(ofi->fdi);
			return;
		}
}

static void do_an_operation(void)
{
	/* Half the time operate on already open files */
	if (tests_random_no(100) < 50)
		operate_on_dir(top_dir);
	else
		operate_on_an_open_file();
}

static void create_test_data(void)
{
	uint64_t i, n;

	grow = 1;
	shrink = 0;
	full = 0;
	operation_count = 0;
	while (!full) {
		do_an_operation();
		++operation_count;
	}
	grow = 0;
	shrink = 1;
	/* Drop to less than 90% full */
	n = operation_count / 40;
	while (n--) {
		uint64_t free;
		uint64_t total;
		for (i = 0; i < 10; ++i)
			do_an_operation();
		free = tests_get_free_space();
		total = tests_get_total_space();
		if ((free * 100) / total >= 10)
			break;
	}
	grow = 0;
	shrink = 0;
	full = 0;
	n = operation_count * 2;
	for (i = 0; i < n; ++i)
		do_an_operation();
}

static void update_test_data(void)
{
	uint64_t i, n;

	grow = 1;
	shrink = 0;
	full = 0;
	while (!full)
		do_an_operation();
	grow = 0;
	shrink = 1;
	/* Drop to less than 50% full */
	n = operation_count / 10;
	while (n--) {
		uint64_t free;
		uint64_t total;
		for (i = 0; i < 10; ++i)
			do_an_operation();
		free = tests_get_free_space();
		total = tests_get_total_space();
		if ((free * 100) / total >= 50)
			break;
	}
	grow = 0;
	shrink = 0;
	full = 0;
	n = operation_count * 2;
	for (i = 0; i < n; ++i)
		do_an_operation();
}

void integck(void)
{
	pid_t pid;
	int64_t rpt;
	uint64_t z;
	char dir_name[256];

	/* Get memory page size for mmap */
	mem_page_size = sysconf(_SC_PAGE_SIZE);
	CHECK(mem_page_size > 0);
	/* Make our top directory */
	pid = getpid();
	printf("pid is %u\n", (unsigned) pid);
	tests_cat_pid(dir_name, "integck_test_dir_", pid);
	if (chdir(dir_name) != -1) {
		/* Remove it if it is already there */
		tests_clear_dir(".");
		CHECK(chdir("..") != -1);
		CHECK(rmdir(dir_name) != -1);
	}
	initial_free_space = tests_get_free_space();
	log10_initial_free_space = 0;
	for (z = initial_free_space; z >= 10; z /= 10)
		++log10_initial_free_space;
	top_dir = dir_new(NULL, dir_name);

	if (!top_dir)
		return;

	srand(pid);

	create_test_data();

	if (!tests_fs_is_rootfs()) {
		close_open_files();
		tests_remount(); /* Requires root access */
	}

	/* Check everything */
	check_run_no += 1;
	dir_check(top_dir);
	check_deleted_files();

	for (rpt = 0; tests_repeat_parameter == 0 ||
				rpt < tests_repeat_parameter; ++rpt) {
		update_test_data();

		if (!tests_fs_is_rootfs()) {
			close_open_files();
			tests_remount(); /* Requires root access */
		}

		/* Check everything */
		check_run_no += 1;
		dir_check(top_dir);
		check_deleted_files();
	}

	/* Tidy up by removing everything */
	close_open_files();
	tests_clear_dir(dir_name);
	CHECK(rmdir(dir_name) != -1);
}

/* Title of this test */

const char *integck_get_title(void)
{
	return "Test file system integrity";
}

/* Description of this test */

const char *integck_get_description(void)
{
	return
		"Create a directory named integck_test_dir_pid " \
		"where pid is the process id. " \
		"Randomly create and delete files and directories. " \
		"Randomly write to and truncate files. " \
		"Un-mount and re-mount test file " \
		"system (if it is not the root file system ). " \
		"Check data. Make more random changes. " \
		"Un-mount and re-mount again. Check again. " \
		"Repeat some number of times. "
		"The repeat count is set by the -n or --repeat option, " \
		"otherwise it defaults to 1. " \
		"A repeat count of zero repeats forever.";
}

int main(int argc, char *argv[])
{
	int run_test;

	/* Set default test repetition */
	tests_repeat_parameter = 1;

	/* Handle common arguments */
	run_test = tests_get_args(argc, argv, integck_get_title(),
			integck_get_description(), "n");
	if (!run_test)
		return 1;
	/* Change directory to the file system and check it is ok for testing */
	tests_check_test_file_system();
	/*
	 * We expect accurate file size from ubifs even after "no space"
	 * errors. And we can mmap.
	 */
	if (strcmp(tests_file_system_type, "ubifs") == 0) {
		check_nospc_files = 1;
		can_mmap = 1;
	}
	/* Do the actual test */
	integck();
	return 0;
}
