/* temp.c  -  Temporary file registry */
/* 
Copyright 1992-1998 Werner Almesberger.
Copyright 1999-2006 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "lilo.h"
#include "common.h"
#ifndef LILO_BINARY
#include "temp.h"
#include "loader.i"


typedef struct _temp {
    char *name;
    struct _temp *next;
} TEMP;


static TEMP *list = NULL;


void temp_register(char *name)
{
    TEMP *new;

    new = alloc_t(TEMP);
    new->name = stralloc(name);
    new->next = list;
    list = new;
}


void temp_unregister(char *name)
{
    TEMP **walk,*this;

    for (walk = &list; *walk; walk = &(*walk)->next)
	if (!strcmp(name,(*walk)->name)) {
	    this = *walk;
	    *walk = this->next;
	    free(this->name);
	    free(this);
	    return;
	}
    die("Internal error: temp_unregister %s",name);
}


void temp_remove(void)
{
    TEMP *next;

    while (list) {
	next = list->next;
	if (remove(list->name) < 0)
	    warn("(temp) %s: %s",list->name,strerror(errno));
	else if (verbose>=2) printf("Removed temporary file %s\n",list->name);
	free(list->name);
	free(list);
	list = next;
    }
}


#else
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#ifdef LCF_BUILTIN
void process(char *file, char *name)
{
    struct stat buf;
    int fd;
    int nchar, nrd, i;
#define NBUF 16
    unsigned char data[NBUF];
    
    if ((fd = open(file, O_RDONLY)) < 0) exit(1);
    if (fstat(fd, &buf)) exit(1);
    
    nchar = buf.st_size;
    printf("struct { int size; unsigned char data[%d]; } %s = { %d, {",
    	nchar, name, nchar);
    while (nchar>0) {
	nrd = (nchar>NBUF ? NBUF : nchar);
	if (read(fd, data, nrd) != nrd) exit(1);
	for (i=0; i<nrd; i++) {
	    printf("%c%3d", i?',':'\n', (int)data[i]);
	}
	nchar -= nrd;
	if (nchar>0) printf(",");
    }
    printf("}};\n");
    close(fd);
    return;
}
#endif

int main(void)
{
    printf("/* begin loader ***/\n");
#ifdef LCF_BUILTIN
    process("first.b", "First");
    process("second.b", "Second");
    process("third.b", "Third");
    process("bitmap.b", "Bitmap");
    process("mbr.b", "Mbr");
    process("mbr2.b", "Mbr2");
    process("chain.b", "Chain");
#ifndef LCF_SOLO_CHAIN
    process("os2_d.b", "Os2_d");
#endif
#endif
    printf("/*** end loader ***/\n");
    return 0;
}

#endif
