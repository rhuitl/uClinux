/****************************************************************************/

/*
 *	fastmem.c -- Simple routines to access fast memory.
 *
 *	(C) Copyright 2002, Greg Ungerer (gerg@snapgear.com)
 */

/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>

/****************************************************************************/
#ifdef __uClinux__
/****************************************************************************/

#define	MAXALLOCS	8

struct atable {
	int	alloced;
	void	*p;
	size_t	size;
};

struct atable	fmem_alloctable[MAXALLOCS];
int		fmem_atablei;

void	*fmem_base = (void *) 0x20000000;
size_t	fmem_alloced;

void *fmalloc(size_t size)
{
	void *p;
	int i;

	/* See if exact match already */
	for (i = 0; (i < MAXALLOCS); i++) {
		if (size == fmem_alloctable[i].size) {
			if (fmem_alloctable[i].alloced == 0) {
				fmem_alloctable[i].alloced = 1;
				return(fmem_alloctable[i].p);
			}
		}
	}

	p = fmem_base;
	fmem_base += size;
	fmem_alloced += size;
	fmem_alloctable[fmem_atablei].alloced = 1;
	fmem_alloctable[fmem_atablei].size = size;
	fmem_alloctable[fmem_atablei].p = p;
	fmem_atablei++;

	return(p);
}

void ffree(void *ptr)
{
	int i;

	for (i = 0; (i < MAXALLOCS); i++) {
		if (ptr == fmem_alloctable[i].p) {
			fmem_alloctable[i].alloced = 0;
			return;
		}
	}

	//free(ptr);
}

/****************************************************************************/
#else
/****************************************************************************/

void *fmalloc(size_t size)
{
	return(malloc(size));
}

void ffree(void *ptr)
{
	free(ptr);
}

/****************************************************************************/
#endif /* __uClinux__ */
/****************************************************************************/
