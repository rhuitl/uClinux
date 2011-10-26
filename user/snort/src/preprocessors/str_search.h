
/*
 *  Copyright (C) 2005 Sourcefire,Inc.
 */
#ifndef __STR_SEARCH_H__
#define __STR_SEARCH_H__

/* Function prototypes  */
typedef int (*MatchFunction)(void *, int, void *);

int  SearchInit(unsigned int num);
int  SearchGetHandle(void);
int  SearchPutHandle(unsigned int id);
int  SearchReInit(unsigned int i);
void SearchFree();
void SearchFreeId(unsigned id);
void SearchAdd(unsigned int mpse_id, char *pat, unsigned int pat_len, int id);
void SearchPrepPatterns(unsigned int mpse_id);
int  SearchFindString(unsigned int mpse_id, char *str, unsigned int str_len, int confine, int (*Match) (void *, int, void *));


void * SearchInstanceNew( void );
void   SearchInstanceFree( void * insance );
void   SearchInstanceAdd( void * instance, char *pat, unsigned int pat_len, int id);
void   SearchInstancePrepPatterns( void * instance );
int    SearchInstanceFindString( void * instance, char *str, unsigned int str_len, int confine, int (*Match) (void *, int, void *));

typedef struct _search_api
{
    int (*search_init)(unsigned int);

    int (*search_reinit)(unsigned int);

    void (*search_free)();

    void (*search_add)(unsigned int, char *, unsigned int, int);

    void (*search_prep)(unsigned int);

    int (*search_find)(unsigned int, char *, unsigned int, int, MatchFunction); 

    /* 6/1/06*/
    void (*search_free_id)(unsigned id);
    
    int (*search_get_handle)(void);
    int (*search_put_handle)(unsigned int);

    void * (*search_instance_new)();
    void   (*search_instance_free)(void * instance);
    void   (*search_instance_add) (void * instance, char *s, unsigned int s_len, int s_id);
    void   (*search_instance_prep)(void * instance );
    int    (*search_instance_find)(void * instance, char *s, unsigned int s_len, int confine, MatchFunction); 
    
} SearchAPI;

extern SearchAPI *search_api;

#endif  /*  __STR_SEARCH_H__  */

