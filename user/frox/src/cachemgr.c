/***************************************

    This is part of frox: A simple transparent FTP proxy
    Copyright (C) 2000 James Hollingshead

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  cachemgr.c -- Return cache files, and implement old cache file removal.

  **************************************/

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/un.h>
#include <string.h>
#include <utime.h>
#include <dirent.h>
#include <stdio.h>
#include <fcntl.h>

#include "common.h"

/* ------------------------------------------------------------- **
** This is the cache manager bit. Each file in the cache has a
** cache_entry structure which is held in a hash table. 
** We now hash the entire URL to get our index into the hash table.
** Each cache_entry structure also has a pair of pointers, and so can
** also be accessed as a doubly linked list with most recently
** accessed files nearer the head.
** 
** A running tally is kept of total file size, and the LRU cache file
** removed whenever this exceeds the maximum. 
**
** When the client wishes to retrieve a URL it sends a string of the
** form "G URL mdtm size type offset\n". If the file is cached then
** the reply is a "R" with the file descriptor to read from attatched to
** the message. If the file isn't cached the reply is a "W" with the
** file descriptor to write to. A "\0" is sent on error.
** ------------------------------------------------------------- */

struct cache_entry {
	struct cache_entry *next, *prev, *collision;

	time_t last_access;
	sstr *filename;
	sstr *uri;
	sstr *mdtm;
	int size, cached;
};

sstr *cachemgr_init(char *cd, int cs);

static void scan_dir(const char *dir);
static int init_dir(const char *dir);
static struct cache_entry *make_entry(char *name);
static struct cache_entry **hash_loc(sstr * key);
static unsigned int hash(sstr * s);
static void add_entry(struct cache_entry *entry);
static void purge_entry(struct cache_entry *entry);
static void remove_entry(struct cache_entry *entry);
static void free_entry(struct cache_entry *p);
static void lru_entry(struct cache_entry *p);
static int parse_urireq(sstr * req, sstr * uri, sstr * mdtm, int *size,
			int *offset, int *type);
static int get_cache_status(int *retfd, sstr * uri, sstr * mdtm, int size,
			    int offset);
static int new_cache_entry(int *retfd, sstr * uri, sstr * mdtm, int size);
void cmgr_run(int fd);
int uri_request(sstr * req, int *retfd);
int open_cachefile(struct cache_entry *p, int offset);
int make_cachefile(struct cache_entry *p);
sstr *get_filename(void);

#define table_size 1024

#define CACHE_HIT       0
#define CACHE_MISS      1
#define CACHE_PARTIAL   2
#define CACHE_ABORT    -1

static struct cache_entry *hash_table[table_size];
static struct cache_entry *head = NULL, *tail = NULL;
static unsigned long total_size = 0;
static int cachesize;
static sstr *cachedir;

/*
 * Fork the cache manager process, and return the path of the unix socket
 * on which it should be contacted.
 */
sstr *cachemgr_init(char *cd, int cs)
{
	int fd;
	struct sockaddr_un listen_addr;
	sstr *socket_file;

	if(config.inetd) {
		write_log(ERROR, "Can't do local caching from inetd");
		return (NULL);
	}
	if(init_dir(cd) == -1)
		return (NULL);

	cachedir = sstr_init(0);
	sstr_apprintf(cachedir, "%s/cache/", cd);
	cachesize = cs;
	socket_file = sstr_dup(cachedir);
	sstr_apprintf(socket_file, "/frox-cache");

	unlink(sstr_buf(socket_file));
	listen_addr.sun_family = AF_UNIX;
	strcpy(listen_addr.sun_path, sstr_buf(socket_file));

	if((fd = socket(PF_UNIX, SOCK_STREAM, 0)) == -1) {
		debug_perr("socket");
		return NULL;
	}

	if(bind(fd, (struct sockaddr *) &listen_addr, sizeof(listen_addr)) ==
	   -1) {
		debug_perr("bind");
		fprintf(stderr, "Check frox has permission to create a"
			" file in %s\n", cd);
		return NULL;
	}

	if(listen(fd, 10) == -1) {
		debug_perr("bind");
		return NULL;
	}
	chown(sstr_buf(socket_file), config.uid, config.gid);

	switch ((cmgrpid = fork())) {
	case -1:
		cmgrpid = 0;
		return (NULL);
	case 0:
		signal(SIGHUP, SIG_IGN);
		break;
	default:
		close(fd);
		return (socket_file);
	}

	sstr_free(socket_file);
	droppriv();

	scan_dir(sstr_buf(cachedir));

	cmgr_run(fd);
	exit(-1);
}

/*
 * Main cache manager loop. Listen for connects on the socket, and serve them
 * (one request per connection). FIXME --- we should exit when the main
 * process does.
 * */
void cmgr_run(int listen)
{
	fd_set reads;
	sstr *buf;
	int cfd, fd;
	buf = sstr_init(MAX_LINE_LEN);

	do {
		fd = accept(listen, NULL, 0);
		if(fd == -1) {
			debug_perr("accept");
			continue;
		}

		FD_ZERO(&reads);
		FD_SET(fd, &reads);
		select(fd + 1, &reads, NULL, NULL, NULL);
		sstr_empty(buf);
		sstr_append_read(fd, buf, MAX_LINE_LEN * 2 - 1);

		switch (sstr_getchar(buf, 0)) {
		case 'G':
			switch (uri_request(buf, &cfd)) {
			case CACHE_ABORT:
				write(fd, "A", 1);
				break;
			case CACHE_HIT:
				send_fd(fd, cfd, 'R');
				close(cfd);
				break;
			case CACHE_MISS:
			case CACHE_PARTIAL:
				send_fd(fd, cfd, 'W');
				close(cfd);
				break;
			}
			break;
		default:
			debug_err("Arrgh - unknown cachemgr cmd");
			write_log(VERBOSE, "%s", sstr_buf(buf));
			write(fd, "\0", 1);
			close(fd);
		}
		close(fd);
	} while(TRUE);
}

/*
 * Take a request for a uri, decide whether it is cached or not, and return a
 * fd for the appropriate cache file if appropriate (either to read or write)
 * */
int uri_request(sstr * req, int *retfd)
{
	static sstr *uri = NULL, *mdtm = NULL;
	int size, offset, type;
	int i;

	if(!uri)
		uri = sstr_init(MAX_LINE_LEN);
	if(!mdtm)
		mdtm = sstr_init(MAX_LINE_LEN);

	parse_urireq(req, uri, mdtm, &size, &offset, &type);

	i = get_cache_status(retfd, uri, mdtm, size, offset);
	if(i != CACHE_MISS)
		return i;

	if(new_cache_entry(retfd, uri, mdtm, size) == -1)
		return CACHE_ABORT;
	else
		return CACHE_MISS;
}

/*
 * Tokenise req, and return the fields individully
 * */
static int parse_urireq(sstr * req, sstr * uri, sstr * mdtm, int *size,
			int *offset, int *type)
{
	sstr_token(req, NULL, " ", 0);
	sstr_token(req, uri, " ", 0);
	sstr_token(req, mdtm, " ", 0);
	*size = sstr_atoi(req);
	sstr_token(req, NULL, " ", 0);
	*type = sstr_atoi(req);
	sstr_token(req, NULL, " ", 0);
	*offset = sstr_atoi(req);
	return 0;
}

/*
 * Check whether the specified url is cached, and whether it is valid. Delete
 * invalid entries.
 * */
static int get_cache_status(int *retfd, sstr * uri, sstr * mdtm, int size,
			    int offset)
{
	struct cache_entry *p;

	p = *hash_loc(uri);

	if(!p && offset) {
		write_log(VERBOSE, "Cache miss. REST requested. Not caching");
		return CACHE_ABORT;
	}
	if(!p) {
		write_log(VERBOSE, "Cache miss");
		return CACHE_MISS;
	}
	if(sstr_cmp(uri, p->uri)) {
		debug_err("Cache file hit, but URIs don't match.");
		purge_entry(p);
		return CACHE_MISS;
	}
	if(sstr_cmp(mdtm, p->mdtm)) {
		write_log(VERBOSE,
			  "Cache file hit, but remote file has changed");
		purge_entry(p);
		return CACHE_MISS;
	}
	if(p->size != size) {
		write_log(VERBOSE,
			  "Ooops. Cache file hit, MDTM hasn't changed,"
			  "but SIZE has.");
		purge_entry(p);
		return CACHE_MISS;
	}

	if((*retfd = open_cachefile(p, offset)) == -1) {
		write_log(VERBOSE,
			  "Cache hit, but offset > cached bytes. Can't cache.");
		return CACHE_ABORT;
	}

	if(set_read_lock(*retfd) == -1) {
		write_log(VERBOSE,
			  "Cache hit, but can't get read lock on file."
			  "Aborting");
		rclose(retfd);
		return CACHE_ABORT;
	}
	if(p->cached == p->size) {
		write_log(VERBOSE, "Cache hit.");
		return CACHE_HIT;
	}
	write_log(VERBOSE, "Partial cache hit only (%d)."
		  " Will now complete cache file", p->cached);
	return CACHE_PARTIAL;
}

/*
 * Create a new cache_entry structure and put it in the linked list and hash
 * table. Also create the file, write its header, and return the file
 * descriptor.
 * */
static int new_cache_entry(int *retfd, sstr * uri, sstr * mdtm, int size)
{
	struct cache_entry *p;

	p = (struct cache_entry *) malloc(sizeof(struct cache_entry));
	p->uri = sstr_dup(uri);
	p->filename = sstr_dup(get_filename());
	p->mdtm = sstr_dup(mdtm);
	p->size = size;
	p->cached = 0;
	p->last_access = time(NULL);
	*retfd = make_cachefile(p);
	if(*retfd == -1) {
		write_log(ERROR, "Creating cache file failed."
			  "Stopping caching");
		free_entry(p);
		return (-1);
	}
	add_entry(p);
	return 0;
}

/*
 * Create the cache file for entry p, write the headers, and return the file
 * descriptor. The first field of the header must be padded to 5 bytes, and
 * states the length of the rest of the header - the magic " + 30" is the
 * total length of the other non string fields. Sorry...
 * */
int make_cachefile(struct cache_entry *p)
{
	int ret;
	sstr *buf;

	ret = creat(sstr_buf(p->filename), S_IRUSR | S_IWUSR);
	if(ret == -1)
		return (-1);

	buf = sstr_init(MAX_LINE_LEN * 2);
	sstr_apprintf(buf, "%03d  %s %012d %01d %s %012lu\n",
		      sstr_len(p->mdtm) + sstr_len(p->uri) + 30,
		      sstr_buf(p->mdtm), p->size, 1, sstr_buf(p->uri),
		      p->last_access);
	sstr_write(ret, buf, 0);
	sstr_free(buf);
	return ret;
}

/*
 * Open the cache file, update the last access time header field, seek to
 * offset, and return the fd. Also move it to the top of the LRU list.
 * */
int open_cachefile(struct cache_entry *p, int offset)
{
	int fd, i;
	struct stat status;
	char buf2[13];
	sstr *buf;

	write_log(VERBOSE, "Opening cache file");
	fd = open(sstr_buf(p->filename), O_RDWR);
	buf = sstr_init(0);

	lseek(fd, 0, SEEK_SET);
	sstr_append_read(fd, buf, 5);
	i = sstr_atoi(buf);

	fstat(fd, &status);
	p->cached = status.st_size - i - 5;
	if(offset > p->cached) {
		sstr_free(buf);
		return -1;
	}

	sstr_append_read(fd, buf, i);
	lru_entry(p);
	p->last_access = time(NULL);
	lseek(fd, sstr_len(buf) - 13, SEEK_SET);
	sprintf(buf2, "%012lu", p->last_access);
	write(fd, buf2, 12);
	lseek(fd, sstr_len(buf), SEEK_SET);
	lseek(fd, offset, SEEK_CUR);
	sstr_free(buf);
	return fd;
}

static void lru_entry(struct cache_entry *p)
{
	if(head == p)
		return;
	if(!p->prev)
		debug_err("Linked list screwed up");

	if(p->next)
		p->next->prev = p->prev;
	else
		tail = p->prev;

	p->prev->next = p->next;

	p->next = head;
	head->prev = p;
	p->prev = NULL;
	head = p;
}

/*
 * Return the address at which a pointer to this uri's cache entry should
 * be stored.
 * */
struct cache_entry **hash_loc(sstr * key)
{
	unsigned int i;
	struct cache_entry *p;

	i = hash(key) % table_size;

	if(hash_table[i] == NULL)
		return (&hash_table[i]);
	if(!sstr_cmp(hash_table[i]->uri, key))
		return (&hash_table[i]);

	/*Collision */
	for(p = hash_table[i];
	    p->collision != NULL && sstr_cmp(p->collision->uri, key);
	    p = p->collision);
	return (&p->collision);
}

/*
 * Link an entry into the linked list, and add it to the hash table.
 * */
void add_entry(struct cache_entry *entry)
{
	struct cache_entry *p, **pp;

	entry->collision = NULL;

	pp = hash_loc(entry->uri);

	if(*pp != NULL) {
		write_log(VERBOSE,
			  "   Already got it - removing old entry.\n");

		remove_entry(*pp);
		pp = hash_loc(entry->uri);
	}
	*pp = entry;

	/*Now add to linked list, based on last access time */
	for(p = head; p != NULL && entry->last_access < p->last_access;
	    p = p->next);
	entry->next = p;
	entry->prev = p ? p->prev : tail;
	if(entry->prev)
		entry->prev->next = entry;
	else
		head = entry;
	if(entry->next)
		entry->next->prev = entry;
	else
		tail = entry;

	/*Round UP to the nearest 1k */
	total_size += 1 + entry->size / 1024;
	if(cachesize)
		while(total_size > cachesize)
			purge_entry(tail);
}

/*
 * Delete the cache file, and remove the cache entry structure.
 * */
void purge_entry(struct cache_entry *entry)
{
	unlink(sstr_buf(entry->filename));
	remove_entry(entry);
}

/*
 * Remove the cache entry structure from the linked list and hash table.
 * */
void remove_entry(struct cache_entry *entry)
{
	unsigned int index;
	struct cache_entry *p;

	if(entry->next)
		entry->next->prev = entry->prev;
	else
		tail = entry->prev;
	if(entry->prev)
		entry->prev->next = entry->next;
	else
		head = entry->next;

	index = hash(entry->uri) % table_size;

	write_log(VERBOSE, "Removing file %s\n", sstr_buf(entry->uri));
	if(hash_table[index] == NULL) {
		debug_err("Arrghhhhhhhhhhhhhhhhh");
		exit(-1);
	}

	if(entry == hash_table[index]) {
		hash_table[index] = entry->collision;
	} else {
		for(p = hash_table[index];
		    p->collision != NULL && p->collision != entry;
		    p = p->collision);
		if(p->collision == NULL) {
			write_log(VERBOSE, "Removing non existant entry!\n");
			exit(-1);
		}
		p->collision = entry->collision;
	}

	total_size -= 1 + entry->size / 1024;
	free_entry(entry);
}

static void free_entry(struct cache_entry *p)
{
	sstr_free(p->filename);
	sstr_free(p->uri);
	sstr_free(p->mdtm);
	free(p);
}

static unsigned int hash(sstr * s)
{
	const char *p;
	unsigned int i;

	p = sstr_buf(s);
	for(i = 0; *p; p++)
		i = 131 * i + *p;
	return i;
}

/* ------------------------------------------------------------- **
** Generate a unique filename within the cache dir. We use current
** time(), and a looping counter. This will only generate 65k
** unique filenames per second - I don't anticipate this being a
** problem!
** -------------------------------------------------------------** */
sstr *get_filename(void)
{
	static sstr *filename = NULL;
	static unsigned int cnt = 0;
	time_t t;

	if(filename == NULL)
		filename = sstr_init(MAX_LINE_LEN);
	sstr_cpy(filename, cachedir);
	time(&t);

	sstr_apprintf(filename, "%02x/%08lx%03lx", cnt & 0x0F,
		      t, (cnt >> 4) & 0xFFF);
	cnt++;
	write_log(VERBOSE, "New filename is %s\n", sstr_buf(filename));
	return (filename);
}

/********************************************************************
 * Stuff for scanning cache dir on startup to build data structures.
 ********************************************************************/

void scan_dir(const char *dir)
{
	DIR *dp;
	struct dirent *entry;
	struct stat status;
	char name[512];

	dp = opendir(dir);
	if(dp == NULL) {
		debug_perr("opendir");
		write_log(ERROR, "Failed to open cache dir %s", dir);
		exit(-1);
	}
	chdir(dir);
	while((entry = readdir(dp)) != NULL) {
		if(entry->d_name[0] == '.')
			continue;
		stat(entry->d_name, &status);
		if(S_ISDIR(status.st_mode))
			scan_dir(entry->d_name);
		else if(S_ISREG(status.st_mode)) {
			struct cache_entry *tmp;

			getcwd(name, 300);
			strcat(name, "/");
			strcat(name, entry->d_name);
			tmp = make_entry(name);
			if(tmp)
				add_entry(tmp);
		}
	}
	chdir("..");
	closedir(dp);
}

/*
 * Read the header from the file, put it into cache entry structure, and add
 * it to the lists.
 * */
struct cache_entry *make_entry(char *name)
{
	struct stat status;
	struct cache_entry *ret;
	char buf[1024];
	int fd, i;

	ret = (struct cache_entry *) malloc(sizeof(struct cache_entry));
	if(ret == NULL) {
		debug_perr("malloc");
		exit(-1);
	}

	stat(name, &status);

	ret->filename = sstr_dup2(name);

	fd = open(name, O_RDONLY);
	read(fd, buf, 5);
	i = atoi(buf);
	if(i > 0 && i < 4096 && read(fd, buf, i) == i) {
		ret->mdtm = sstr_dup2(strtok(buf, " "));
		ret->size = atoi(strtok(NULL, " "));
		strtok(NULL, " ");	/*Type */
		ret->uri = sstr_dup2(strtok(NULL, " \r\n"));
		ret->last_access = strtoul(strtok(NULL, " \r\n"), NULL, 10);
		close(fd);
	} else {
		close(fd);
		write_log(VERBOSE, "Invalid file %s\n", name);
		unlink(name);
		sstr_free(ret->filename);
		free(ret);
		return (NULL);
	}

	ret->cached = status.st_size - i - 5;
	if(ret->size != ret->cached)
		write_log(VERBOSE, "Partial file %s (%d/%d)\n", name,
			  ret->cached, ret->size);

	return (ret);
}

int init_dir(const char *dir)
{
	int i;
	struct stat status;
	sstr *name;

	name = sstr_init(0);
	sstr_apprintf(name, "%s/cache", dir);
	if(stat(sstr_buf(name), &status) == -1) {
		if(mkdir(sstr_buf(name), S_IRWXU) == -1) {
			write_log(ERROR, "Unable to make cache dir %s",
				  sstr_buf(name));
			sstr_free(name);
			return (-1);
		}
		chown(sstr_buf(name), config.uid, config.gid);
	}
	for(i = 0; i < 16; i++) {
		sstr_cpy2(name, dir);
		sstr_apprintf(name, "/cache/%02x", i);
		if(stat(sstr_buf(name), &status) == -1) {
			write_log(IMPORT, "Making cache dir %s",
				  sstr_buf(name));
			if(mkdir(sstr_buf(name), S_IRWXU) == -1) {
				write_log(ERROR,
					  "Unable to make cache dir %s",
					  sstr_buf(name));
				sstr_free(name);
				return (-1);
			}
			chown(sstr_buf(name), config.uid, config.gid);
		} else if(!S_ISDIR(status.st_mode)) {
			write_log(ERROR, "%s is not a directory",
				  sstr_buf(name));
			sstr_free(name);
			return (-1);
		}
	}
	sstr_free(name);
	return (0);
}

#ifdef TESTING
#include "../test/test-cm.c"
#endif
