/* temp.h  -  Temporary file registry

Copyright 1992-1995 Werner Almesberger.
Copyright 1999-2004 John Coffman.
All rights reserved.

Licensed under the terms contained in the file 'COPYING' in the 
source directory.

*/


#ifndef TEMP_H
#define TEMP_H

#define temp_check(x) ((x)!=LILO)

void temp_register(char *name);

/* Registers a file for removal at exit. */

void temp_unregister(char *name);

/* Removes the specified file from the temporary file list. */

void temp_remove(void);

/* Removes all temporary files. */

#endif
