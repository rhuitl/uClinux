/*
*  $Id$
*
*   mpse.c
*    
*   An abstracted interface to the Multi-Pattern Matching routines,
*   thats why we're passing 'void *' objects around.
*
*   Copyright (C) 2002 SourceFire, Inc
*   Marc A Norton <mnorton@sourcefire.com>
*
*   Updates:
*   3/06 - Added AC_BNFA search
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
**
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bitop.h"
#include "bnfa_search.h"
#include "acsmx.h"
#include "acsmx2.h"
#include "sfksearch.h"
#include "mpse.h"  

#include "profiler.h"
#ifdef PERF_PROFILING
#include "snort.h"
PreprocStats mpsePerfStats;
#endif

static UINT64 s_bcnt=0;

typedef struct _mpse_struct {

  int    method;
  void * obj;
  int    verbose;

}MPSE;

void * mpseNew( int method )
{
   MPSE * p;

   p = (MPSE*)malloc( sizeof(MPSE) );
   if( !p ) return NULL;

   p->method=method;
   p->verbose=0;
   p->obj   =NULL;
   s_bcnt  =0;

   switch( method )
   {
     case MPSE_AC_BNFA:
       p->obj=bnfaNew();
       return (void*)p;
     break;
     case MPSE_AC:
       p->obj = acsmNew();
       return (void*)p;
     break;
     case MPSE_ACF:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_FULL  );
       return (void*)p;
     break;
     case MPSE_ACS:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSE  );
       return (void*)p;
     break;
     case MPSE_ACB:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_BANDED  );
       return (void*)p;
     break;
     case MPSE_ACSB:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSEBANDS  );
       return (void*)p;
     break;
     case MPSE_LOWMEM:
       p->obj = KTrieNew();
       return (void*)p;
     break;

     default:
       free(p);
       return 0;
     break; 
   }
}

void   mpseVerbose( void * pvoid )
{
  MPSE * p = (MPSE*)pvoid;
  p->verbose = 1;
} 


void   mpseFree( void * pvoid )
{
  MPSE * p = (MPSE*)pvoid;
 
  switch( p->method )
   {
     case MPSE_AC_BNFA:
         bnfaFree((bnfa_struct_t*)p->obj);
         break;

     case MPSE_AC:
       if(p->obj)acsmFree(p->obj);
       free(p);
       return ;
     break;

     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       if(p->obj)acsmFree2(p->obj);
       free(p);
       return ;
     break;

     case MPSE_LOWMEM:
       return ;
     break;

     default:
       return ;
     break; 
   }
}

int  mpseAddPattern ( void * pvoid, void * P, int m, 
             unsigned noCase,unsigned offset, unsigned depth,  void* ID, int IID )
{
  MPSE * p = (MPSE*)pvoid;

  switch( p->method )
   {
     case MPSE_AC_BNFA:
       return bnfaAddPattern( (bnfa_struct_t*)p->obj, (unsigned char *)P, m,
              noCase, ID );
     break;

     case MPSE_AC:
       return acsmAddPattern( (ACSM_STRUCT*)p->obj, (unsigned char *)P, m,
              noCase, offset, depth, ID, IID );
     break;

     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       return acsmAddPattern2( (ACSM_STRUCT2*)p->obj, (unsigned char *)P, m,
              noCase, offset, depth, ID, IID );
     break;

     case MPSE_LOWMEM:
       return KTrieAddPattern( (KTRIE_STRUCT *)p->obj, (unsigned char *)P, m,
                                noCase, ID );
     break;

     default:
       return -1;
     break; 
   }
}

void mpseLargeShifts   ( void * pvoid, int flag )
{
  MPSE * p = (MPSE*)pvoid;
 
  switch( p->method )
   {
     default:
       return ;
     break; 
   }
}

int  mpsePrepPatterns  ( void * pvoid )
{
  int retv;
  MPSE * p = (MPSE*)pvoid;

  switch( p->method )
   {
     case MPSE_AC_BNFA:
       retv = bnfaCompile( (bnfa_struct_t*) p->obj);
     break;
     
     case MPSE_AC:
       retv = acsmCompile( (ACSM_STRUCT*) p->obj);
     break;
     
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       retv = acsmCompile2( (ACSM_STRUCT2*) p->obj);
     break;
     
     case MPSE_LOWMEM:
       return KTrieCompile( (KTRIE_STRUCT *)p->obj);
     break;

     default:
       retv = 1;
     break; 
   }
  
  return retv;
}

void mpseSetRuleMask ( void *pvoid, BITOP * rm )
{
  MPSE * p = (MPSE*)pvoid;

  switch( p->method )
   {
     default:
       return ;
     break; 
   }


}
int mpsePrintInfo( void *pvoid )
{
  MPSE * p = (MPSE*)pvoid;

  fflush(stderr);
  fflush(stdout);
  switch( p->method )
   {
     case MPSE_AC_BNFA:
      bnfaPrintInfo( (bnfa_struct_t*) p->obj );
     break;
     case MPSE_AC:
      return acsmPrintDetailInfo( (ACSM_STRUCT*) p->obj );
     break;
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
      return acsmPrintDetailInfo2( (ACSM_STRUCT2*) p->obj );
      break;
     
     default:
       return 1;
     break; 
   }
   fflush(stderr);
   fflush(stdout);

 return 0;
}

int mpsePrintSummary( )
{
   fflush(stderr);
   fflush(stdout);

   acsmPrintSummaryInfo();
   acsmPrintSummaryInfo2();
   bnfaPrintSummary();
   
   fflush(stderr);
   fflush(stdout);

   return 0;
}

int mpseSearch( void *pvoid, unsigned char * T, int n, 
    int ( *action )(void*id, int index, void *data), 
    void * data ) 
{
  MPSE * p = (MPSE*)pvoid;
  int ret;
  PROFILE_VARS;

  PREPROC_PROFILE_START(mpsePerfStats);
  s_bcnt += n;
  
  switch( p->method )
   {
     case MPSE_AC_BNFA:
      /* return is actually the state */
      ret = bnfaSearch( (bnfa_struct_t*) p->obj, T, n, action, data, 0 /* start-state */ );
      PREPROC_PROFILE_END(mpsePerfStats);
      return ret;
     break;

     case MPSE_AC:
      ret = acsmSearch( (ACSM_STRUCT*) p->obj, T, n, action, data );
      PREPROC_PROFILE_END(mpsePerfStats);
      return ret;
     break;
     
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
      ret = acsmSearch2( (ACSM_STRUCT2*) p->obj, T, n, action, data );
      PREPROC_PROFILE_END(mpsePerfStats);
      return ret;
     break;

     case MPSE_LOWMEM:
        ret = KTrieSearch( (KTRIE_STRUCT *)p->obj, T, n, action, data );
        PREPROC_PROFILE_END(mpsePerfStats);
        return ret;
     break;

     default:
       PREPROC_PROFILE_START(mpsePerfStats);
       return 1;
     break; 
   }

}


UINT64 mpseGetPatByteCount( )
{
  return s_bcnt; 
}

void mpseResetByteCount( )
{
    s_bcnt = 0;
}

 
