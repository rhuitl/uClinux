#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "linux_list.h"

struct buffer {
	size_t max_size;
	size_t cur_size;
	unsigned int num_elems;
	struct list_head head;
};

struct buffer_node {
	struct list_head head;
	size_t size;
	char data[0];
};

struct buffer *buffer_create(size_t max_size);
void buffer_destroy(struct buffer *b);
unsigned int buffer_len(struct buffer *b);
int buffer_add(struct buffer *b, const void *data, size_t size);
void buffer_del(struct buffer *b, void *data);
void buffer_iterate(struct buffer *b, 
		    void *data, 
		    int (*iterate)(void *data1, void *data2));

#endif
