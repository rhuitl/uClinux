#ifndef _TESTING_H
#define _TESTING_H

/* Testing code. */
#ifdef JUST_TESTING

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/utsname.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <dirent.h>

/* We don't use all of these. */
static int modtest_uname(struct utsname *buf) __attribute__((unused));
static long modtest_create_module(const char *name, size_t size)
__attribute__((unused));
static void *modtest_fopen(const char *path, const char *mode)
__attribute__((unused));
static int modtest_open(const char *path, int flags, mode_t mode)
__attribute__((unused));
static int modtest_stat(const char *file_name, struct stat *buf)
__attribute__((unused));
static int modtest_lstat(const char *file_name, struct stat *buf)
__attribute__((unused));
static DIR *modtest_opendir(const char *name) __attribute__((unused));
static int modtest_system(const char *string) __attribute__((unused));
static int modtest_rename(const char *oldpath, const char *newpath)
__attribute__((unused));
static long modtest_init_module(void *map, unsigned long size,
				const char *optstring) __attribute__((unused));
static long modtest_delete_module(const char *modname, unsigned int flags)
__attribute__((unused));

static int modtest_readlink(const char *path, char *buf, size_t bufsiz)
__attribute__((unused));

static int modtest_uname(struct utsname *buf)
{
	strcpy(buf->sysname, "Linux");
	strcpy(buf->nodename, "fakenodename");
	strcpy(buf->release, getenv("MODTEST_UNAME"));
	strcpy(buf->version, "Fakeversion");
	strcpy(buf->machine, "fakemachine");
	return 0;
}

static long modtest_create_module(const char *name, size_t size)
{
	if (getenv("MODTEST_DO_CREATE_MODULE"))
		return 0;
	errno = ENOSYS;
	return -1;
}

static long modtest_init_module(void *map, unsigned long size,
				const char *optstring)
{
	if (getenv("MODPROBE_WAIT")) {
		int fd;
		const char *file = getenv("MODPROBE_WAIT");

		printf("Looping on %s\n", file);
		fflush(stdout);
		while ((fd = open(file, O_RDONLY)) < 0)
			sleep(1);
		close(fd);
		printf("Removing %s\n", file);
		unlink(file);
	}
	if (getenv("MODTEST_INSERT_PROC")) {
		int fd = modtest_open("/proc/modules", O_APPEND|O_WRONLY, 0);
		write(fd, getenv("MODPROBE_MODULE"), strlen(getenv("MODPROBE_MODULE")));
		write(fd, " 1000 1 -\n", strlen(" 1000 1 -\n"));
		close(fd);
		return 0;
	}
	if (getenv("MODTEST_DUMP_INIT")) {
		while (size) {
			int ret;
			ret = write(2, map, size);
			if (ret < 0) exit(1);
			size -= ret;
			map += ret;
		}
	} else		
		printf("INIT_MODULE: %lu %s\n", size, optstring);
	
	return 0;
}

static long modtest_delete_module(const char *modname, unsigned int flags)
{
	char flagnames[100];

	if (getenv("MODPROBE_WAIT")) {
		int fd;
		const char *file = getenv("MODPROBE_WAIT");

		printf("Looping on %s\n", file);
		fflush(stdout);
		while ((fd = open(file, O_RDONLY)) < 0)
			sleep(1);
		close(fd);
		printf("Removing %s\n", file);
		fflush(stdout);
		unlink(file);
	}
	flagnames[0] = '\0';
	if (flags & O_EXCL)
		strcat(flagnames, "EXCL ");
	if (flags & O_TRUNC)
		strcat(flagnames, "TRUNC ");
	if (flags & O_NONBLOCK)
		strcat(flagnames, "NONBLOCK ");
	if (flags & ~(O_EXCL|O_TRUNC|O_NONBLOCK))
		strcat(flagnames, "UNKNOWN ");

	printf("DELETE_MODULE: %s %s\n", modname, flagnames);
	return 0;
}

static const char *modtest_mapname(const char *path)
{
	unsigned int i;
	char envname[64];

	for (i = 0; ; i++) {
		char *name; 
		sprintf(envname, "MODTEST_OVERRIDE%u", i);
		name = getenv(envname);
		if (!name)
			break;
		if (strcmp(path, name) == 0) {
			sprintf(envname, "MODTEST_OVERRIDE_WITH%u", i);
			return getenv(envname);
		}
	}
	return path;
}

static void *modtest_fopen(const char *path, const char *mode)
{
	return fopen(modtest_mapname(path), mode);
}

static int modtest_open(const char *path, int flags, mode_t mode)
{
	return open(modtest_mapname(path), flags, mode);
}

static int modtest_stat(const char *file_name, struct stat *buf)
{
	return stat(modtest_mapname(file_name), buf);
}

static int modtest_lstat(const char *file_name, struct stat *buf)
{
	return lstat(modtest_mapname(file_name), buf);
}

static DIR *modtest_opendir(const char *name)
{
	return opendir(modtest_mapname(name));
}

static int modtest_system(const char *string)
{
	if (getenv("MODTEST_DO_SYSTEM"))
		return system(string);
	printf("SYSTEM: %s\n", string);
	return 0;
}

static int modtest_rename(const char *oldpath, const char *newpath)
{
	return rename(modtest_mapname(oldpath), modtest_mapname(newpath));
}

static int modtest_readlink(const char *path, char *buf, size_t bufsiz)
{
	return readlink(modtest_mapname(path), buf, bufsiz);
}

#ifdef CONFIG_USE_ZLIB
#include <zlib.h>
static gzFile *modtest_gzopen(const char *filename, const char *mode)
__attribute__((unused));

static gzFile *modtest_gzopen(const char *filename, const char *mode)
{
	return gzopen(modtest_mapname(filename), mode);
}
#endif

/* create_module call */
#undef create_module
#define create_module modtest_create_module

#define uname modtest_uname
#define delete_module modtest_delete_module
#define init_module modtest_init_module
#define open modtest_open
#define fopen modtest_fopen
#define stat(name, ptr) modtest_stat(name, ptr)
#define lstat(name, ptr) modtest_lstat(name, ptr)
#define opendir modtest_opendir
#define system modtest_system
#define rename modtest_rename
#define readlink modtest_readlink
#define gzopen modtest_gzopen

#endif /* JUST_TESTING */
#endif /* _TESTING_H */

