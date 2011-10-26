/*
**  util.c
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

//#define MDEBUG

static unsigned msize=0;

void * xmalloc(size_t byteSize)
{
#ifdef MDEBUG
   int * data = (int*) malloc( byteSize + 4 );
   unsigned m = msize;

   if(data)memset(data,0,byteSize+4);
#else
   int * data = (int*) malloc( byteSize );
   if(data)memset(data,0,byteSize);
#endif

   if( data == NULL )
    {
        return NULL;
    }

#ifdef MDEBUG

	msize += byteSize + 4;

	*data = byteSize+4;

    //printf("** xmalloc msize=%u, allocbytes=%d, msize=%u  %x\n", m, byteSize+4, msize, data);

	data++;

    return data;

#else

	msize += byteSize;

    return data;
#endif
}

void xfree( void * p )
{
#ifdef MDEBUG
   unsigned m = msize;
   int  *q = (int*)p;
   q--;
   msize -= *q;

   free(q);
      
#else
   
   free(p);

#endif

   
}

void xshowmem()
{
#ifdef MDEBUG
	  printf("xmalloc-mem: %u bytes\n",msize);
#endif
}

char *xstrdup(const char *str)
{
	char *data = (char *)xmalloc( strlen(str) + 1 );
    
	if(data == NULL)
    {
        return NULL;
    }

    strcpy(data,str);

    return data;
}

