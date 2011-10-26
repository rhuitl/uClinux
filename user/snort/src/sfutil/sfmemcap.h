/*
**  sfmemcap.h
*/
#ifndef __SF_MEMCAP_H__
#define __SF_MEMCAP_H__

typedef struct
{
   unsigned memused;
   unsigned memcap;
   int      nblocks;

}MEMCAP;

void     sfmemcap_init(MEMCAP * mc, unsigned nbytes);
MEMCAP * sfmemcap_new( unsigned nbytes );
void     sfmemcap_delete( MEMCAP * mc );
void   * sfmemcap_alloc(MEMCAP * mc, unsigned nbytes);
void     sfmemcap_showmem(MEMCAP * mc );
void     sfmemcap_free( MEMCAP * mc, void * memory);
char   * sfmemcap_strdup(MEMCAP * mc, const char *str);
void   * sfmemcap_dupmem(MEMCAP * mc, void * src, int n );

#endif
