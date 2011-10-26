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
#include <dlfcn.h>

#include "log.h"
#include "modinfo.h"

#define MODNAME "modinfo"
/*
 * modinfo_create:  Create and initialize a modinfo structure
 *
 * Arguments:       nVars = # of variables the modinfo should support
 *
 * Return values:   Returns NULL on failure, else a valid ptr on success.
 */

ModInfo *modinfo_create( int nVars ){
  ModInfo *res;
  int i;

  if( (res = malloc( sizeof( *res ))) == NULL )
    return NULL;

  res->nVars = nVars;
  if( (res->vars = malloc( sizeof( *res->vars ) * res->nVars )) == NULL ){
    free( res );
    return NULL;
  }
  
  for( i=0; i< nVars; i++ ){
    res->vars[ i ].type = MODINFO_TYPE_INT;
    strcpy( res->vars[ i ].varname, "NoName" );
    strcpy( res->vars[ i ].description, "NoDesc" );
  }

  return res;
}

/*
 * modinfo_destroy:  Destroy a modinfo structure.
 *
 * Arguments:        minfo = Modinfo to destroy
 */

void modinfo_destroy( ModInfo *minfo ){
  free( minfo->vars );
  free( minfo );
}

/*
 * modinfo_varname_set:  Set a variable name inside the variable list
 *
 * Arguments:            minfo = Modinfo to set the variable name within
 *                       vnum  = Variable number to set the name of (base = 0)
 *                       newname = New name for the variable.
 */

void modinfo_varname_set( ModInfo *minfo, int vnum, const char *newname ){
  strncpy( minfo->vars[ vnum ].varname, newname, 
	   sizeof( minfo->vars[ vnum ].varname ) - 1 );
  minfo->vars[ vnum ].varname[ sizeof( minfo->vars[ vnum ].varname )-1] = '\0';
}

/*
 * modinfo_desc_set:     Set a description of a variable inside the variable
 *                       list
 *
 * Arguments:            minfo = Modinfo to set the variable name within
 *                       vnum  = Variable number to set the name of (base = 0)
 *                       newdesc = New description for the variable
 */

void modinfo_desc_set( ModInfo *minfo, int vnum, const char *newdesc ){
  int len;

  len = sizeof( minfo->vars[ vnum ].description );
  strncpy( minfo->vars[ vnum ].description, newdesc, len - 1 );
  minfo->vars[ vnum ].description[ len - 1 ] = '\0';
}


/*
 * modinfo_query_so:   Query a shared library for it's module information.
 *            
 * Arguments:          soname = Pathname to the so to query.
 *
 * Return values:      Returns NULL on failure, else a valid pointer to a new
 *                     modinfo structure.
 */

ModInfo *modinfo_query_so( const char *soname ){
  void *dlhandle;
  ModInfo_QueryFunc qfunc;
  ModInfo *res;

  if( (dlhandle = dlopen( soname, RTLD_LAZY | RTLD_GLOBAL )) == NULL ){
    camserv_log( MODNAME, dlerror());
    return NULL;
  }

  if( !(qfunc = dlsym( dlhandle, "modinfo_query" ))){
    camserv_log( MODNAME, dlerror());
    dlclose( dlhandle );
    return NULL;
  }

  res = qfunc();
  return res;
}

static
const char *query_modinfo_type( int type ){
  if( type & MODINFO_TYPE_INT )   return "(int)";
  if( type & MODINFO_TYPE_FLOAT ) return "(float)";
  if( type & MODINFO_TYPE_STR )   return "(string)";
  return "ERR";
}

void modinfo_dump( const ModInfo *minfo ){
  int i;

  for( i=0; i< minfo->nVars; i++ ){
    fprintf( stderr, "[%d] %-10s %s\n\t\"%s\"\n",
	     i, query_modinfo_type( minfo->vars[ i ].type ),
	     minfo->vars[ i ].varname, 
	     minfo->vars[ i ].description );
  }
}
