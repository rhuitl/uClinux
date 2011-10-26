/* $Id$ */
/*
** Copyright (C) 2002 Martin Roesch <roesch@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif


/*
 * This is used to allocate a list of fixed size objects in a static
 * memory pool aside from the concerns of alloc/free
 */

/* $Id$ */
#include "mempool.h"

/* Function: int mempool_init(MemPool *mempool,
 *                            PoolCount num_objects, size_t obj_size)
 * 
 * Purpose: initialize a mempool object and allocate memory for it
 * Args: mempool - pointer to a MemPool struct
 *       num_objects - number of items in this pool
 *       obj_size    - size of the items
 * 
 * Returns: 0 on success, 1 on failure
 */ 

int mempool_init(MemPool *mempool, PoolCount num_objects, size_t obj_size)
{
    PoolCount i;
    
    if(mempool == NULL)
        return 1;

    if(num_objects < 1)
        return 1;

    if(obj_size < 1)
        return 1;

    mempool->obj_size = obj_size;
    
    /* this is the basis pool that represents all the *data pointers
       in the list */
    mempool->datapool = calloc(num_objects, obj_size);
    
    
    if(mempool->datapool == NULL)
    {
        return 1;
    }

    mempool->listpool = calloc(num_objects, sizeof(SDListItem));

    if(mempool->listpool == NULL)
    {
        /* well, that sucked, lets clean up */
        fprintf(stderr, "mempool: listpool is null\n");
        free(mempool->datapool);
        return 1;
    }

    mempool->bucketpool = calloc(num_objects, sizeof(MemBucket));

    if(mempool->bucketpool == NULL)
    {
        fprintf(stderr, "mempool: bucketpool is null\n");
        free(mempool->datapool);
        free(mempool->listpool);
        return 1;
    }

    /* sets up the 2 memory lists */
    if(sf_sdlist_init(&mempool->used_list, NULL))
    {
        fprintf(stderr, "mempool: used_list failed\n");
        free(mempool->datapool);
        free(mempool->listpool);
        free(mempool->bucketpool);
        return 1;
    }

    if(sf_sdlist_init(&mempool->free_list, NULL))
    {
        fprintf(stderr, "mempool: free_list failed\n");
        free(mempool->datapool);
        free(mempool->listpool);
        free(mempool->bucketpool);
        return 1;
    }


    for(i=0; i<num_objects; i++)
    {
        SDListItem *itemp;
        MemBucket *bp;

        bp = &mempool->bucketpool[i];
        itemp = &mempool->listpool[i];
        
        /* each bucket knows where it resides in the list */
        bp->key = itemp;

#ifdef TEST_MEMPOOL        
        printf("listpool: %p itemp: %p diff: %u\n",
               mempool->listpool, itemp,
               (((char *) itemp) -
                ((char *) mempool->listpool)));
#endif /* TEST_MEMPOOL */
               
        bp->data = ((char *) mempool->datapool) + (i * mempool->obj_size);
        
#ifdef TEST_MEMPOOL        
        printf("datapool: %p bp.data: %p diff: %u\n",
               mempool->datapool,
               mempool->datapool + (i * mempool->obj_size),
               (((char *) bp->data) -
                ((char *) mempool->datapool)));
#endif /* TEST_MEMPOOL */
        

        if(sf_sdlist_append(&mempool->free_list,                           
                            &mempool->bucketpool[i],
                            &mempool->listpool[i]))
        {
            fprintf(stderr, "mempool: free_list_append failed\n");
            free(mempool->datapool);
            free(mempool->listpool);
            free(mempool->bucketpool);
            return 1;
        }

        mempool->free++;
    }

    mempool->used = 0;
    mempool->total = num_objects;
    
    return 0;
}

/* Function: int mempool_destroy(MemPool *mempool) 
 * 
 * Purpose: destroy a set of mempool objects
 * Args: mempool - pointer to a MemPool struct
 * 
 * Returns: 0 on success, 1 on failure
 */ 
int mempool_destroy(MemPool *mempool)
{
    if(mempool == NULL)
        return 1;

    free(mempool->listpool);

    /* TBD - callback to free up every stray pointer */
    bzero(mempool, sizeof(MemPool));
    
    return 0;    
}


/* Function: MemBucket *mempool_alloc(MemPool *mempool);
 * 
 * Purpose: allocate a new object from the mempool
 * Args: mempool - pointer to a MemPool struct
 * 
 * Returns: a pointer to the mempool object on success, NULL on failure
 */ 
MemBucket *mempool_alloc(MemPool *mempool)
{
    SDListItem *li = NULL;
    MemBucket *b;
    
    if(mempool == NULL)
    {
        return NULL;
    }

    if(mempool->free <= 0)
    {
        return NULL;
    }

    /* get one item off the free_list,
       put one item on the usedlist
     */

    li = mempool->free_list.head;

    mempool->free--;
    if((li == NULL) || sf_sdlist_remove(&mempool->free_list, li))
    {
        printf("Failure on sf_sdlist_remove\n");
        return NULL;
    }
        
    
    mempool->used++;

    if(sf_sdlist_append(&mempool->used_list, li->data, li))
    {
        printf("Failure on sf_sdlist_append\n");
        return NULL;
    }

    /* TBD -- make configurable */
    b = li->data;
    bzero(b->data, mempool->obj_size);
    
    return b;
}


void mempool_free(MemPool *mempool, MemBucket *obj)
{       
    if(sf_sdlist_remove(&mempool->used_list, obj->key))
    {
        printf("failure on remove from used_list");
        return;
    }
    
    mempool->used--;

    /* put the address of the membucket back in the list */
    if(sf_sdlist_append(&mempool->free_list, obj, obj->key))
    {
        printf("failure on add to free_list");
        return;
    }

    mempool->free++;    
    return;
}

#ifdef TEST_MEMPOOL

#define SIZE 36
int main(void)
{
    MemPool test;
    MemBucket *bucks[SIZE];
    MemBucket *bucket = NULL;
    int i;
    long long a = 1;

    //char *stuffs[4] = { "eenie", "meenie", "minie", "moe" };
    char *stuffs2[36] =
        {  "1eenie", "2meenie", "3minie", " 4moe",
           "1xxxxx", "2yyyyyy", "3zzzzz", " 4qqqq",
           "1eenie", "2meenie", "3minie", " 4moe",
           "1eenie", "2meenie", "3minie", " 4moe",
           "1eenie", "2meenie", "3minie", " 4moe",
           "1eenie", "2meenie", "3minie", " 4moe",
           "1eenie", "2meenie", "3minie", " 4moe",
           "1eenie", "2meenie", "3minie", " 4moe",
           "1eenie", "2meenie", "3minie", " 4moe"
        };
    
    if(mempool_init(&test, 36, 256))
    {
        printf("error in mempool initialization\n");
    }

    for(i = 0; i < 36; i++)
    {
        if((bucks[i] = mempool_alloc(&test)) == NULL)
        {
            printf("error in mempool_alloc: i=%d\n", i);
            continue;
        }

        bucket = bucks[i];

        bucket->data = strncpy(bucket->data, stuffs2[i], 256);
        printf("bucket->key: %p\n", bucket->key);
        printf("bucket->data: %s\n", (char *) bucket->data);
    }

    for(i = 0; i < 2; i++)
    {
        mempool_free(&test, bucks[i]);
        bucks[i] = NULL;
    }
    
    for(i = 0; i < 14; i++)
    {
        if((bucks[i] = mempool_alloc(&test)) == NULL)
        {
            printf("error in mempool_alloc: i=%d\n", i);
            continue;
        }

        bucket = bucks[i];

        bucket->data = strncpy(bucket->data, stuffs2[i], 256);
        printf("bucket->key: %p\n", bucket->key);
        printf("bucket->data: %s\n", (char *) bucket->data);
    }

    printf("free: %u, used: %u\n", test.free, test.used);

    
    return 0;
}
#endif /* TEST_MEMPOOL */

