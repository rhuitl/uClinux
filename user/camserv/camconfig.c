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
#include <string.h>

#include "log.h"
#include "camconfig.h"
#include "hash.h"

#define HASH_MAX_SECTIONS  HASHCOUNT_T_MAX
#define HASH_MAX_ENTRIES   HASHCOUNT_T_MAX

struct camconfig_section_st {
  char section_name[ MAX_SECTION_NAME + 1 ];
  hash_t *entryhash;
};

struct camconfig_st {
  hash_t *mainhash;  /* Hash of CamConfigSection's */
};

/*
 * section_new:  Create and initialize a new CamConfigSection structure
 *
 * Arguments:    name = New name for the config section
 *
 * Return values:  Returns NULL on failure, else a pointer to new
 *                 CamConfigSection structure.
 */

static
CamConfigSection *section_new( const char *name ){
  CamConfigSection *res;

  if( (res = malloc( sizeof( *res ))) == NULL )
    return NULL;

  strncpy( res->section_name, name, sizeof( res->section_name ) -1 );
  res->section_name[ sizeof( res->section_name ) - 1 ] = '\0';
  if( (res->entryhash = hash_create( HASH_MAX_SECTIONS, NULL, NULL )) == NULL){
    free( res );
    return NULL;
  }

  return res;
}

/*
 * section_add_pair:  Add or update a key/value pair in a section.  
 *
 * Arguments:         section = Section to update key/value pair in.
 *                    key     = Key to add
 *                    val     = Value associated with 'key'
 *
 * Return values:     Returns -1 on failure, 0 on success.
 */

static
int section_add_pair( CamConfigSection *section, char *key,
		      char *value )
{
  char *keydup, *valdup;
  hnode_t *hnode;

  if( (hnode = hash_lookup( section->entryhash, key )) != NULL ){
    if( (valdup = strdup( value )) == NULL )
      return -1;

    /* Replacing an existing value */
    free( hnode_get( hnode ) );
    hnode_put( hnode, valdup );
    return 0;
  }

  if( (keydup = strdup( key )) == NULL )
    return -1;

  if( (valdup = strdup( value )) == NULL ){
    free( keydup );
    return -1;
  }

  if( !hash_alloc_insert( section->entryhash, keydup, valdup )){
    free( keydup );
    free( valdup );
    return -1;
  }

  return 0;
}

/*
 * section_dest:  Destroy a camconfig section, and all the key/value pairs
 *                held within.
 *
 * Argumetns:     section = Section to destroy.
 */

static
void section_dest( CamConfigSection *section ){
  hscan_t hs;
  hnode_t *node;

  hash_scan_begin( &hs, section->entryhash );
  while( (node = hash_scan_next( &hs ))) {
    char *key, *val;

    key = hnode_getkey( node );
    val = hnode_get( node );
    hash_scan_delete( section->entryhash, node );
    section->entryhash->freenode( node, section->entryhash->context );
    free( key );
    free( val );
  }
  hash_destroy( section->entryhash );
  free( section );
}

/*
 * camconfig_new:   Create and initialize a new camconfig structure.
 *
 * Return values:   Returns NULL on failure, else a valid pointer to a new
 *                  camconfig structure.
 */

CamConfig *camconfig_new(){
  CamConfig *res;

  if( (res = malloc( sizeof( *res )))== NULL )
    return NULL;

  if( (res->mainhash = hash_create( HASH_MAX_SECTIONS, NULL, NULL )) == NULL ){
    free( res );
    return NULL;
  }

  return res;
}

/*
 * camconfig_dest:  Destroy a camconfig structure, all the sections and
 *                  key/value pairs within.
 *
 * Arguments:       ccfg = camconfig structure to destroy
 */

void camconfig_dest( CamConfig *ccfg ){
  hscan_t hs;
  hnode_t *node;

  hash_scan_begin( &hs, ccfg->mainhash );
  while( (node = hash_scan_next( &hs ))) {
    char *key;
    CamConfigSection *val;

    key = hnode_getkey( node );
    val = hnode_get( node );
    hash_scan_delete( ccfg->mainhash, node );
    ccfg->mainhash->freenode( node, ccfg->mainhash->context );
    free( key );
    section_dest( val );
  }
  hash_destroy( ccfg->mainhash );
  free( ccfg );
}

/*
 * camconfig_add_section:  Add a new section into a camconfig structure.
 *                         Note that duplicate section names are disallowed.
 *
 * Arguments:              ccfg = Camconfig structure to add section to.
 *                         newsec = New section name to add.
 *
 * Return valueS:          Returns NULL on failure, else a valid pointer to
 *                         the new section that was created and added to
 *                         the camconfig structure.
 */

static
CamConfigSection *camconfig_add_section( CamConfig *ccfg, char *newsec )
{
  CamConfigSection *res;
  char *keyval;
  hnode_t *node;

  if( hash_lookup( ccfg->mainhash, newsec ) != NULL ){
    camserv_log( "camconfig", "Section \"%s\" multi-defined in cfg",
		 newsec );
    return NULL;
  }
    
  if( (res = section_new( newsec )) == NULL )
    return NULL;

  if( (keyval = strdup( newsec )) == NULL ){
    section_dest( res );
    return NULL;
  }

  if( (node = hnode_create( res )) == NULL ){
    section_dest( res );
    free( keyval );
    return NULL;
  }

  hash_insert( ccfg->mainhash, node, keyval );
  return res;
}

/*
 * camconfig_read:  Create a camconfig structure, read a file containing
 *                  sections, and key/value pairs into it, and return it.
 *
 * Arguments:       fp = FILE to read camconfig data from.
 *
 * Return Values:   Returns NULL on failure, else a valid pointer to a new
 *                  camconfig structure.
 */

CamConfig *camconfig_read( FILE *fp ){
  CamConfigSection *current_section;
  CamConfig *ccfg;
  char buf[ 1024 ], *cp, *endcp, key[ 1024 ], value[ 1024 ];
  int lineno;

  if( (ccfg = camconfig_new()) == NULL ){
    camserv_log( "camconfig", "Error allocating memory for config!");
    return NULL;
  }

  current_section = NULL;
  lineno = 0;
  while( fgets( buf, sizeof( buf ), fp ) != NULL ){
    lineno++;
    if( buf[ 0 ] == '#' || buf[ 0 ] == '\n' ) 
      continue;

    if( buf[ 0 ] == '[' ) {  /* Begin a section */
      if( (endcp = strrchr( buf, ']' )) == NULL ){
	camserv_log( "camconfig", "Malformed section on line: %d", lineno );
	continue;
      }
      cp = &buf[ 1 ];
      *endcp = '\0';

      if( (current_section = camconfig_add_section( ccfg, cp )) == NULL ){
	camserv_log( "camconfig", "Error adding section! (malloc?)");
	camconfig_dest( ccfg );
	return NULL;
      }
      continue;
    } 

    /* key-val pair */
    if( current_section == NULL ){
      camserv_log( "camconfig","Line %d not in a section!", lineno );
      continue; /* Non-fatal error */
    }

    if( sscanf( buf, "%s %[^\n]s", key, value ) != 2 ){
      camserv_log( "camconfig", "Malformed input on line %d", lineno );
      continue;
    }

    if( section_add_pair( current_section, key, value ) == -1 ){
      camserv_log( "camconfig", "Malloc failure adding key-value pair!" );
      camconfig_dest( ccfg );
      return NULL;
    }
  }
  return ccfg;
}

/*
 * camconfig_set_str:  Set a string value of a key/value pair in the ccfg.
 *
 * Arguments:          ccfg = Camconfig struct to set the key/value pair in.
 *                     section = Section to contain 'key'
 *                     key  = Key to set (copied in locally)
 *                     val  = Value associated with the key. (copied in local)
 *
 * Return values:      Returns -1 on failure (add to an undefined section, or
 *                     malloc failure), else 0 on success.
 */

int camconfig_set_str( CamConfig *ccfg, char *secname, char *key, char *val ){
  hnode_t *node;
  CamConfigSection *section;

  /* Can't add to an undefined section! */
  if( (node = hash_lookup( ccfg->mainhash, secname )) == NULL )
    return -1;
  
  section = hnode_get( node );
  return section_add_pair( section, key, val );
}

/*
 * camconfig_set_int:  Set an int value of a key/value pair in the ccfg.
 *
 * Arguments:          ccfg = Camconfig struct to set the key/value pair in.
 *                     secname = Section to contain 'key'
 *                     key  = Key to set (copied in locally)
 *                     val  = Value associated with the key.
 *
 * Return values:      Returns -1 on failure (add to an undefined section, or
 *                     malloc failure), else 0 on success.
 */

int camconfig_set_int( CamConfig *ccfg, char *secname, char *key, int val ){
  char buf[ 1024 ];

  sprintf( buf, "%d", val );
  return camconfig_set_str( ccfg, secname, key, buf );
}

/*
 * camconfig_query_str:  Query a string value from the camconfig structure.
 *
 * Arguments:            ccfg = Camconfig struct to get the key/value pair from
 *                       secname = Section containing 'key'
 *                       key  = Key of the item
 *
 * Return values:        Returns -1 on failure (add to an undefined section, or
 *                       malloc failure), else 0 on success.
 */

const char *camconfig_query_str( CamConfig *ccfg, char *secname, char *key ){
  hnode_t *node;
  CamConfigSection *section;

  if( (node = hash_lookup( ccfg->mainhash, secname )) == NULL )
    return NULL;

  section = hnode_get( node );

  if( (node = hash_lookup ( section->entryhash, key )) == NULL )
    return NULL;

  return hnode_get( node );
}

/*
 * camconfig_query_int:  Query an int value from the camconfig structure.
 *
 * Arguments:            ccfg = Camconfig struct to get the key/value pair from
 *                       secname = Section containing 'key'
 *                       key  = Key of the item
 *                       err  = Location to place an error flag.
 *
 * Return values:        On failure, -1 will be returned, and *err will be
 *                       set to 1, else *err will be 0, and the return value
 *                       will be a valid integer representation of the value.
 */

int camconfig_query_int( CamConfig *ccfg, char *secname, char *key, int *err){
  hnode_t *node;
  CamConfigSection *section;
  int res;

  if( (node = hash_lookup( ccfg->mainhash, secname )) == NULL ){
    *err = 1;
    return -1;
  }

  section = hnode_get( node );

  if( (node = hash_lookup ( section->entryhash, key )) == NULL ){
    *err = 1;
    return -1;
  }

  *err = 0;
  sscanf( hnode_get( node ), "%d", &res );
  return res;
}  

/*
 * camconfig_query_def_float:  Query float value from the camconfig structure,
 *                             and use a default if it does not exist.
 *
 * Arguments:            ccfg = Camconfig struct to get the key/value pair from
 *                       secname = Section containing 'key'
 *                       key  = Key of the item
 *                       def = Default value to return if the key is not found.
 *
 * Return values:        On failure, 'def' is returned, else the value 
 *                       converted to (float) will be returned.
 */

float camconfig_query_def_float( CamConfig *ccfg, char *secname, char *key,
				 float def )
{
  hnode_t *node;
  CamConfigSection *section;

  if( (node = hash_lookup( ccfg->mainhash, secname )) == NULL ){
    camserv_log( "camconfig", "Using default of \"%f\" for [%s]:%s",
		 def, secname, key );
    return def;
  }

  section = hnode_get( node );

  if( (node = hash_lookup ( section->entryhash, key )) == NULL ){
    camserv_log( "camconfig", "Using default of \"%f\" for [%s]:%s",
		 def, secname, key );
    return def;
  }

  return atof( hnode_get( node ));
}  

/*
 * camconfig_query_def_int:  Query int value from the camconfig structure,
 *                           and use a default if it does not exist.
 *
 * Arguments:            ccfg = Camconfig struct to get the key/value pair from
 *                       secname = Section containing 'key'
 *                       key  = Key of the item
 *                       def = Default value to return if the key is not found.
 *
 * Return values:        On failure, 'def' is returned, else the value 
 *                       converted to (int) will be returned.
 */

int camconfig_query_def_int( CamConfig *ccfg, char *secname, char *key,int def)
{
  int err, res;

  res = camconfig_query_int( ccfg, secname, key, &err );
  if( err == 1 ){
    camserv_log( "camconfig", "Using default of \"%d\" for [%s]:%s",
		 def, secname, key );
    return def;
  }  else 
    return res;
}

static void printhash( hash_t *hash ){
  hscan_t hs;
  hnode_t *hn;

  hash_scan_begin(&hs, hash);
  while ((hn = hash_scan_next(&hs)))
    printf("%s\t%s\n", (char*) hnode_getkey(hn),
	   (char*) hnode_get(hn));
}

static void printcfg( CamConfig *ccfg ){
  hscan_t hs;
  hnode_t *hn;

  hash_scan_begin(&hs, ccfg->mainhash);
  while ((hn = hash_scan_next(&hs))){
    CamConfigSection *sec;

    sec = hnode_get( hn );
    printf("-------%s--------\n", sec->section_name );
    printhash( sec->entryhash );
  }
}

