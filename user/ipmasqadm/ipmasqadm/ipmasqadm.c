/*
 *
 *	ipmasqadm - IP MASQ administration tool
 *
 *
 *	Copyright (c) 1997 Juan Jose Ciarlante
 *
 *	Author: Juan Jose Ciarlante <jjciarla@raiz.uncu.edu.ar>
 *
 * 	$Id: ipmasqadm.c,v 0.4 1998/06/17 19:36:58 jjo Exp jjo $  
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <dlfcn.h>
#include "ipmasqadm.h"

/* Quite global ...*/
const char *progname = NULL;

void usage(FILE *out, int exit_status)
{
	fprintf(out, "usage: %s MODULE [opts] \n", progname);
	exit (exit_status);
}

int main(int argc, const char *argv[])
{
	const char *modname;	/* module name */
	char *mod_filename;	/* module filename: /usr/lib/ipmasqadm/MOD.so */
	void *dlp;
	int (*mod_main) (int, const char *[]);

	progname = argv[0];
	if (argc<2)
		usage(stderr, 1);

	modname = argv[1];

	mod_filename=malloc(strlen(LIBDIR)+strlen(modname)+1+3+1);
        if (!mod_filename) {
        	perror("malloc()");
                return 1;
        }
        
	sprintf(mod_filename, LIBDIR "/%s.so", modname);

	/* 
	 *	Open module file
	 */
	dlp=dlopen(mod_filename, RTLD_NOW);
	if (!dlp) {
		fprintf(stderr, "dlopen(): %s\n", dlerror());
		return 1;
	}

	/* 
	 *	Fetch entry address (masqmod_main)
	 */
	mod_main=dlsym(dlp, MASQ_MOD_MAIN);
	if (!mod_main) {
		fprintf(stderr, "dlsym(\"%s\"): %s\n", "masqmod_main", dlerror());
		return 1;
	}
	--argc;
	++argv;

	/*
	 *	Here we go ...
	 */
	return mod_main(argc, argv);
}
