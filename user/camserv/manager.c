/*  camserv - An internet streaming picture application
 *
 *  Copyright (C) 1999-2002  Jon Travis (jtravis@p00p.org)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include "list.h"
#include "manager.h"

typedef struct picture_bin_st {

  char *picture_data;       /* Picture information */
  size_t picture_size;      
  int picture_id;
  int nClients;             /* # of clients using the bin */
} Picture_Bin;

/*
 * The manager routines take care of how many data bins we are using, and
 * who is using them.  This keeps the amount of memory low, if multiple
 * clients are waiting for the same picture.
 */

static list_t *Manager_BinList = NULL;
static int BinList_Size = 0;
static int Current_Picture_Id = 0;

/*
 * picture_bin_new:  Create a new picture bin to store a picture and
 *                   the users connected with it.  
 *
 * Return values:    Returns NULL on failure, else a valid pointer to
 *                   a fresh chunk of memory containing the picture bin
 */

static
Picture_Bin *picture_bin_new( ){
  Picture_Bin *res;

  if( (res = malloc( sizeof( *res ))) == NULL ){
    return NULL;
  }

  res->picture_data = NULL;
  res->picture_size = 0;
  res->nClients = 0;
  res->picture_id = 0;
  return res;
}

static
void picture_bin_dest( Picture_Bin *bin ){
  if( bin->picture_data != NULL )
    free( bin->picture_data );

  free( bin );
}

/*
 * manager_new_picture:  
 * Tell the manager routines to manage a new picture.  This
 * routine will attempt to allocate space to store the 
 * picture within the list, in addition to cleaning out old
 * pictures with no connected clients. 
 *
 * Arguments: picture_data = Caller-allocated memory containing
 *                           the picture to send to the client. 
 *                           The caller should noc free the 
 *                           picture data after passing in here, it
 *                           will be freed upon bin cleanup.
 *
 *            pic_size     = Amount of data in picture_data
 * 
 *            max_clients  = Max # of clients to support per picture
 *
 * Return values:  Returns -1 if the routine failed to manage
 *                 the picture (Malloc failure), else 0
 */

int
manager_new_picture( char *picture_data, size_t pic_size, int max_clients ){
  Picture_Bin *new_bin;
  lnode_t *binlist_node, *node_next;

  if( (new_bin = picture_bin_new( max_clients )) == NULL ){
    return -1;
  }

  new_bin->picture_data = picture_data;
  new_bin->picture_size = pic_size;
  new_bin->picture_id = Current_Picture_Id++;

  if( (binlist_node = lnode_create( new_bin )) == NULL ){
    fprintf( stderr, "Manager; Couldn't allocate lnode!\n");
    picture_bin_dest( new_bin );
    return -1;
  }

  if( Manager_BinList == NULL ) {
    if( (Manager_BinList = list_create( -1 )) == NULL ){
      fprintf( stderr, "Manager:  Couldn't allocate linked list!\n");
      lnode_destroy( binlist_node );
      picture_bin_dest( new_bin );
      return -1;
    }
  }

  list_prepend( Manager_BinList, binlist_node );
  BinList_Size++;

  binlist_node = list_next( Manager_BinList,
			    binlist_node ); /* To avoid the new one */
  for( ;
       binlist_node != NULL; 
       binlist_node = node_next )
  {
    Picture_Bin *node_data;
    
    node_data = binlist_node->data;
    node_next = list_next( Manager_BinList, binlist_node );
    
    /* If the bin doesn't have any clients, just delete it */
    
    if( node_data->nClients == 0 ){
      list_delete( Manager_BinList, binlist_node );
      picture_bin_dest( node_data );
      lnode_destroy( binlist_node );
      BinList_Size--;
    } 
  }      
  return 0;
}


/*
 * manager_new_client:  Add a client to the list of managed
 *                      clients & picture bins.  This routine will
 *                      figure out the most up-to-date picture to 
 *                      send the client, and return information that
 *                      the client will need to know to send the
 *                      picture, and free themselves up after they
 *                      have sent it.
 *
 * Arguments:
 *                      pic_data = Storage place to put the pointer to the
 *                                 picture data for the client to use
 *          
 *                      pic_size = Storage place to put the picture size
 *
 *                      pic_id   = Storage place to put the picture ID
 *
 * Return values:       Returns NULL on failure (unknown), else a valid
 *                      pointer which must be passed to manager_dest_client
 *                      when the client is done using the picture.
 */

void *manager_new_client( char **pic_data, size_t *pic_size, 
			  int *pic_id )
{
  lnode_t *binlist_head_node;
  Picture_Bin *pic_bin;

  if( Manager_BinList == NULL ) 
    return NULL;

  binlist_head_node = list_first( Manager_BinList );
  if( binlist_head_node == NULL ){
    return NULL;
  }
  
  pic_bin = binlist_head_node->data;

  *pic_data = pic_bin->picture_data;
  *pic_size = pic_bin->picture_size;
  *pic_id   = pic_bin->picture_id;
  pic_bin->nClients++;

  return binlist_head_node;
}

/*
 * manager_dest_client:  Remove a client from using a managed bin.
 *                      
 * Arguments:            reset_data = Data returned from manager_new_client
 *
 * Return values:  Returns 0 on success, -1 on failure.
 */

int manager_dest_client( void *reset_data ){
  Picture_Bin *pic_bin;
  lnode_t *binlist_node;

  binlist_node = reset_data;
  pic_bin = binlist_node->data;
  
  pic_bin->nClients--;
  return 0;
}
