/* $Id$ */
/*
 ** Copyright (C) 2003-2006 Sourcefire, Inc.
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
/*
   sfthreshold.c

   This file contains functions that glue the generic thresholding2 code to 
   snort.

   dependent files:  sfthd sfxghash sfghash sflsq 
                     util mstring

   Copyright (C) 2003 Sourcefire,Inc.
   Marc Norton

   2003-05-29:
     cmg: Added s_checked variable  --
       when this is 1, the sfthreshold_test will always return the same 
       answer until
       sfthreshold_reset is called

   2003-11-3:
     man: cleaned up and added more startup printout.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mstring.h"
#include "util.h"
#include "parser.h"

#include "sfthd.h"
#include "sfthreshold.h"
#include "snort.h"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <errno.h>

/*
     Data
*/
static int          s_memcap  = 1024 * 1024;
static THD_STRUCT * s_thd     = 0;
static int          s_enabled = 1;
static int          s_checked = 0; /**< have we evaluated this yet? */
static int          s_answer  = 0; /**< what was the last return value? */


/*
*   Fatal Integer Parser
*   Ascii to Integer conversion with fatal error support
*/
static unsigned xatou( char * s , char * etext)
{
    unsigned val;

    char *endptr;
  
    while( *s == ' ' ) s++;

    if( *s == '-' ) 
       FatalError("%s(%d) => *** %s\n*** Invalid unsigned integer - negative sign found, input: %s\n",
                            file_name, file_line, etext ,s );

    errno = 0;
    
    /*
    *  strtoul - errors on win32 : ERANGE (VS 6.0)
    *            errors on linux : ERANGE, EINVAL
    */ 
    val =(unsigned)strtoul(s,&endptr,10);
    
    if(errno || endptr == s)
    {
       FatalError("%s(%d) => *** %s\n*** Invalid integer input: %s\n",
                            file_name, file_line, etext, s );
    } 

    return val;
}

/*

     Parse Threshold Rule option parameters for each RULE

     'threshold: type limit|threshold|both, track by_src|by_dst, count #, seconds #;'

*/
void ParseThreshold2( THDX_STRUCT * thdx, char * s )
{
      int    i = 0;
      char * argv[100], * t;
      int    argc;
      int    count_flag=0;
      int    seconds_flag=0;
      int    type_flag=0;
      int    tracking_flag=0;
      
      if( !s_enabled )
          return ;

      memset( thdx, 0, sizeof(THDX_STRUCT) );

      thdx->priority = -1; /* Make this lower than standalone threshold command defaults ??? */
      
      /* Parse all of the args - they come in pairs */      
      for( argc=0, t = strtok(s," ,\n");  argc < 100 &&  t != 0 ;  argc++, t = strtok(0," ,\n") )
      {
          argv[ argc ] = t;           
      }

      /* Parameter Check - enough args ?*/
      if( argc != 8 )
      {
          /* Fatal incorrect argument count */ 
          FatalError("%s(%d) => Threshold-RuleOptionParse: incorrect argument count, should be 4 pairs\n",
                            file_name, file_line);
      }

      for(i=0;i<argc;i++)
      {
        if( strcmp(argv[i],"count") == 0  )
         {
            i++;
            thdx->count = xatou(argv[i],"threshold: count");
            count_flag++;
         }
        else if( strcmp(argv[i],"seconds") == 0  )
         {
            i++;
            thdx->seconds = xatou(argv[i],"threshold: seconds");
            seconds_flag++;
         }
        else if( strcmp(argv[i],"type") == 0  )
         {
            i++;
            if( strcmp(argv[i],"limit") == 0 )
            {
               thdx->type = THD_TYPE_LIMIT;
            }
            else if( strcmp(argv[i],"threshold") == 0 )
            {
               thdx->type = THD_TYPE_THRESHOLD;
            }
            else if( strcmp(argv[i],"both") == 0 )
            {
               thdx->type = THD_TYPE_BOTH;
            }
            else
            {
                /* Fatal incorrect threshold type */
                 FatalError("%s(%d) => Threshold-RuleOptionParse: incorrect 'type' argument \n",
                                file_name, file_line);
            }
            type_flag++;
         }
        else if( strcmp(argv[i],"track") == 0  )
         {
            i++;
            if( strcmp(argv[i],"by_src") == 0 )
            {
                thdx->tracking = THD_TRK_SRC;
            }
            else if( strcmp(argv[i],"by_dst") == 0 )
            {
                thdx->tracking = THD_TRK_DST;
            }
            else
            {
                /* Fatal incorrect threshold type */
                 FatalError("%s(%d) => Threshold-RuleOptionParse: incorrect tracking type\n",
                                file_name, file_line);
            }
            tracking_flag++;
         }
        else
         {
            /* Fatal Out Here - Unknow Option */
            FatalError("%s(%d) => Threshold-RuleOptionParse: unknown argument \n",
                            file_name, file_line);
         }
     }

     if( (count_flag + tracking_flag + type_flag + seconds_flag ) != 4 )
     {
         /* Fatal - incorrect argument count */
         FatalError("%s(%d) => Threshold-RuleOptionParse: incorrect argument count\n",
                        file_name, file_line);
     }
}

/*

   Process the 'config threshold: memcap #bytes, option2-name option2-value, ...'

   config threshold: memcap #bytes
*/
void ProcessThresholdOptions(char *options)
{
      int     i = 0;
      char ** args;
      int     nargs;
      char ** oargs;
      int     noargs;
      
      if( !s_enabled )
          return ;

      args = mSplit(options,",",10,&nargs,0);  /* get rule option pairs */

      for(i=0;i<nargs;i++)
      {
          oargs = mSplit(options," ",2,&noargs,0);  /* get rule option pairs */

          if( strcmp(oargs[0],"memcap") == 0  )
          {
             s_memcap = xatou(oargs[1],"config threshold: memcap");
          }
          else
          {
             FatalError("%s(%d) => Threshold-RuleOptionParse: unknown argument\n",file_name, file_line);
          }
          mSplitFree(&oargs, noargs);
     }
     mSplitFree(&args, nargs);
}

/*
   threshold gen_id #, sig_id #, type limit|threshold|both, track by_src|by_dst,  count #, seconds #

   8/25/03 - added support for a global threshold, uses sid = 0, and is applied after all other thresholding so 
   a sid specific threshold or suppress command has precedence...
*/
void ParseSFThreshold( FILE * fp, char * rule )
{
     char        **args, **oargs;
     int         nargs = 0, noargs = 0;
     THDX_STRUCT thdx;
     int         count_flag=0;
     int         seconds_flag=0;
     int         type_flag=0;
     int         tracking_flag=0;
     int         genid_flag=0;
     int         sigid_flag=0;
     int         i;

     memset( &thdx, 0, sizeof(THDX_STRUCT) );

     while( (*rule <= ' ') && (*rule > 0) ) rule++; /* skip whitespace */
     while( (*rule  > ' ') ) rule++;  /* skip 'threshold' */

     args = mSplit(rule,",",15,&nargs,0);  /* get rule option pairs */

     for( i=0; i<nargs; i++ )
     {
         oargs = mSplit(args[i]," ",2,&noargs,0);  /* get rule option pairs */
         
         if( noargs != 2 )
         {
             FatalError("%s(%d) => Threshold Parse: argument pairing error\n", file_name, file_line);
         }

         if( strcmp(oargs[0],"type")==0 )
         {
            if( strcmp(oargs[1],"limit") == 0 )
            {
               thdx.type = THD_TYPE_LIMIT;
            }
            else if( strcmp(oargs[1],"threshold") == 0 )
            {
               thdx.type = THD_TYPE_THRESHOLD;
            }
            else if( strcmp(oargs[1],"both") == 0 )
            {
               thdx.type = THD_TYPE_BOTH;
            }
            else
            {
                /* Fatal incorrect threshold type */
                 FatalError("%s(%d) => Threshold-Parse: incorrect 'type' argument \n", file_name, file_line);
            }
            type_flag++;
         }

         else if( strcmp(oargs[0],"track")==0 )
         {
            if( strcmp(oargs[1],"by_src") == 0 )
            {
                thdx.tracking = THD_TRK_SRC;
            }
            else if( strcmp(oargs[1],"by_dst") == 0 )
            {
                thdx.tracking = THD_TRK_DST;
            }
            else
            {
                /* Fatal incorrect threshold type */
                 FatalError("%s(%d) => Threshold-Parse: incorrect tracking type\n", file_name, file_line);
            }
            tracking_flag++;
         }

         else if( strcmp(oargs[0],"count")==0 )
         {
            thdx.count = xatou(oargs[1],"threshold: count");
            count_flag++;
         }

         else if( strcmp(oargs[0],"seconds")==0 )
         {
            thdx.seconds = xatou(oargs[1],"threshold: seconds");
            seconds_flag++;
         }

         else if( strcmp(oargs[0],"gen_id")==0 )
         {
            thdx.gen_id =  xatou(oargs[1],"threshold: gen_id");
            genid_flag++;

            if( oargs[1][0]== '-' ) 
                FatalError("%s(%d) => Threshold-Parse: gen_id < 0 not supported  '%s %s'\n",
                                    file_name, file_line, oargs[0],oargs[1]);
         }

         else if( strcmp(oargs[0],"sig_id")==0 )
         {
            thdx.sig_id = xatou(oargs[1],"threshold: sig_id");
            sigid_flag++;
            if( oargs[1][0]== '-' ) 
                FatalError("%s(%d) => Threshold-Parse: sig_id < 0 not supported  '%s %s'\n",
                                    file_name, file_line, oargs[0],oargs[1]);
         }
         else
         {
             /* Fatal incorrect threshold type */
             FatalError("%s(%d) => Threshold-Parse: unsupported option : %s %s\n",
                                file_name, file_line, oargs[0],oargs[1]);
         }

         mSplitFree(&oargs, noargs);
     }

     if( (count_flag + tracking_flag + type_flag + seconds_flag + genid_flag + sigid_flag) != 6 )
     {
        /* Fatal - incorrect argument count */
        FatalError("%s(%d) => Threshold-Parse: incorrect argument count\n",file_name, file_line);
     }

     if( sfthreshold_create( &thdx  ) )
     {
        if( thdx.sig_id == 0 )
        {
           FatalError("%s(%d) => Global Threshold-Parse: could not create a threshold object "
                            "-- only one per gen_id=%u!\n",
                                file_name, file_line,thdx.gen_id);
        }
        else
        {
           if( thdx.gen_id ==  0 )
           {
              FatalError("%s(%d) => Global Threshold-Parse: could not create a threshold object "
                            "-- a gen_id < 0 requires a sig_id < 0, sig_id=%u !\n",
                                    file_name, file_line, thdx.sig_id);
           }
           else
           {
              FatalError("%s(%d) => Threshold-Parse: could not create a threshold object -- only one per sig_id=%u!\n",
                                    file_name, file_line, thdx.sig_id);
           }
        }
     }

     mSplitFree(&args, nargs);
     mSplitFree(&oargs, noargs);
}

/*

    Parse basic CIDR block  - [!]a.b.c.d/bits

*/
static void parseCIDR( THDX_STRUCT * thdx, char * s )
{
   char        **args;
   int          nargs;

   if (*s == '!')
   {
       thdx->not_flag = 1;
       s++;
       while( (*s <= ' ') && (*s > 0) ) s++; /* skip whitespace */
   }

   args = mSplit( s , "/", 2, &nargs, 0 );  /* get rule option pairs */

   if( !nargs || nargs > 2  )
   {
       FatalError("%s(%d) => Suppress-Parse: argument pairing error\n", file_name, file_line);
   }

   /*
   *   Keep IP in network order
   */
   thdx->ip_address = inet_addr( args[0] );   

   if( nargs == 2 )
   {
       int      i;
       int      nbits;
       unsigned mask;

       nbits = xatou( args[1],"suppress: cidr mask bits" );
       mask  = 1 << 31;

       for( i=0; i<nbits; i++ )
       {
          thdx->ip_mask |= mask;
          mask >>= 1;
       }

       /* 
          Put mask in network order 
       */
       thdx->ip_mask = htonl(thdx->ip_mask);       
   }
   else
   {
       thdx->ip_mask = 0xffffffff; /* requires exact ip match */
   }

   /* just in case the network is not right */
   thdx->ip_address &= thdx->ip_mask;

   mSplitFree(&args, nargs);
}

/*

   suppress gen_id #, sig_id #, track by_src|by_dst, ip cidr'

*/
void ParseSFSuppress( FILE * fp, char * rule )
{

     char        **args, **oargs;
     int         nargs, noargs;
     THDX_STRUCT thdx;
     int         genid_flag=0;
     int         sigid_flag=0;
     int         i;

     memset( &thdx, 0, sizeof(THDX_STRUCT) );

     while( (*rule <= ' ') && (*rule > 0) ) rule++; /* skip whitespace */
     while( (*rule  > ' ') ) rule++;  /* skip 'suppress' */

     args = mSplit(rule,",",15,&nargs,0);  /* get rule option pairs */

     thdx.type      =  THD_TYPE_SUPPRESS;
     thdx.priority  =  THD_PRIORITY_SUPPRESS;
     thdx.ip_address=  0;  //default is all ip's- ignore this event altogether
     thdx.ip_mask   =  0;
     thdx.tracking  =  THD_TRK_DST;

     for( i=0; i<nargs; i++ )
     {
         oargs = mSplit(args[i]," ",2,&noargs,0);  /* get rule option pairs */
         if( noargs != 2 )
         {
             FatalError("%s(%d) => Suppress-Parse: argument pairing error\n", file_name, file_line);
         }

         if( strcmp(oargs[0],"track")==0 )
         {
            if( strcmp(oargs[1],"by_src") == 0 )
            {
                thdx.tracking = THD_TRK_SRC;
            }
            else if( strcmp(oargs[1],"by_dst") == 0 )
            {
                thdx.tracking = THD_TRK_DST;
            }
            else
            {
                /* Fatal incorrect threshold type */
                 FatalError("%s(%d) => Suppress-Parse: incorrect tracking type\n", file_name, file_line);
            }
         }

         else if( strcmp(oargs[0],"gen_id")==0 )
         {
            char * endptr;
            thdx.gen_id = strtoul(oargs[1],&endptr,10);
            genid_flag++;
            if( oargs[1][0]=='-' )
                FatalError("%s(%d) => Suppress-Parse: gen_id < 0 is not supported, '%s %s' \n",
                                file_name, file_line, oargs[0],oargs[1]);
         }

         else if( strcmp(oargs[0],"sig_id")==0 )
         {
            char * endptr;
            thdx.sig_id = strtoul(oargs[1],&endptr,10);
            sigid_flag++;
            if( oargs[1][0]=='-' )
                FatalError("%s(%d) => Suppress-Parse: sig_id < 0 is not supported, '%s %s' \n",
                                file_name, file_line, oargs[0],oargs[1]);
         }

         else if( strcmp(oargs[0],"ip")==0 )
         {
            parseCIDR( &thdx, oargs[1] );
         }
         mSplitFree(&oargs, noargs);
     }

     if( ( genid_flag + sigid_flag) != 2 )
     {
         /* Fatal - incorrect argument count */
         FatalError("%s(%d) => Suppress-Parse: incorrect argument count\n", file_name, file_line);
     }

     if( sfthreshold_create( &thdx  ) )
     {
         FatalError("%s(%d) => Suppress-Parse: could not create a threshold object\n", file_name, file_line);
     }

     mSplitFree(&args, nargs);
}

/*

    Init Thresholding - call when starting to parsing rules - so we can add them 

    if the init function is not called, than all thresholding is turned off because
    the thd_struct pointer is null.

*/
int sfthreshold_init()
{
   if( !s_enabled )
       return 0;

   /* Check if already init'd */
   if( s_thd )
       return 0;

   s_thd = sfthd_new( s_memcap );
   if( !s_thd )
   {
       return -1;
   }

   return 0;
}

/*
*  DEBUGGING ONLY
*/
void print_netip(unsigned long ip)
{
    struct in_addr addr;
    char *str;

    addr.s_addr= ip;
    str = inet_ntoa(addr);

    if(str)
        printf("%s", str);

    return;
}

/*
*  DEBUGGING ONLY
*/
void print_thdx( THDX_STRUCT * thdx )
{
    if( thdx->type != THD_TYPE_SUPPRESS )
    {
       printf("THRESHOLD: gen_id=%u, sig_id=%u, type=%d, tracking=%d, count=%d, seconds=%d \n",
                       thdx->gen_id,
                       thdx->sig_id,
                       thdx->type,
                       thdx->tracking,
                       thdx->count,
                       thdx->seconds );
    }
    else
    {
       printf("SUPPRESS: gen_id=%u, sig_id=%u, tracking=%d, not_flag=%d ",
                       thdx->gen_id,
                       thdx->sig_id,
                       thdx->tracking,
                       thdx->not_flag);

       printf(" ip=");
       print_netip(thdx->ip_address); 
       printf(", mask=" );
       print_netip(thdx->ip_mask); 
       printf("\n");
    }
}

static 
void ntoa( char * buff, int blen, unsigned ip )
{
   SnortSnprintf(buff,blen,"%d.%d.%d.%d", ip&0xff,(ip>>8)&0xff,(ip>>16)&0xff,(ip>>24)&0xff );
}

#define PRINT_GLOBAL   0
#define PRINT_LOCAL    1
#define PRINT_SUPPRESS 2
/*
 *   type = 0 : global
 *          1 : local
 *          2 : suppres
 */
int print_thd_node( THD_NODE *p , int type )
{
    char buf[STD_BUF+1];
    char buffer[80];

    memset(buf, 0, STD_BUF+1);

    switch( type )
    {
    case 0: /* global */
           if(p->type == THD_TYPE_SUPPRESS ) return 0;
           if(p->sig_id != 0 ) return 0;
           break;
           
    case 1: /* local */
           if(p->type == THD_TYPE_SUPPRESS ) return 0;
           if(p->sig_id == 0 || p->gen_id == 0 ) return 0;
           break;
           
    case 2: /*suppress  */
           if(p->type != THD_TYPE_SUPPRESS ) return 0;
           break;
    }
    
    /*     sfsnprintfappend(buf, STD_BUF, "| thd-id=%d", p->thd_id ); */

    
    if( p->gen_id == 0 )
    {
        SnortSnprintfAppend(buf, STD_BUF, "| gen-id=global");
    }
    else
    {
        SnortSnprintfAppend(buf, STD_BUF, "| gen-id=%-6d", p->gen_id );
    }
    if( p->sig_id == 0 )
    {
        SnortSnprintfAppend(buf, STD_BUF, " sig-id=global" );
    }
    else
    {
        SnortSnprintfAppend(buf, STD_BUF, " sig-id=%-10d", p->sig_id );
    }
    
    /*               
    if( p->type == THD_TYPE_SUPPRESS )
    sfsnprintfappend(buf, STD_BUF, " type=Suppress ");
    */      
    if( p->type != THD_TYPE_SUPPRESS )
    {
        if( p->type == THD_TYPE_LIMIT )
            SnortSnprintfAppend(buf, STD_BUF, " type=Limit    ");
        
        if( p->type == THD_TYPE_THRESHOLD )
            SnortSnprintfAppend(buf, STD_BUF, " type=Threshold");
        
        if( p->type == THD_TYPE_BOTH )
            SnortSnprintfAppend(buf, STD_BUF, " type=Both     ");
    }
    
    SnortSnprintfAppend(buf, STD_BUF, " tracking=%s", (!p->tracking) ? "src" : "dst" );

    if( p->type == THD_TYPE_SUPPRESS )
    {
        ntoa(buffer,80,p->ip_address);
        if (p->not_flag)
            SnortSnprintfAppend(buf, STD_BUF, "ip=!%-16s", buffer);
        else
            SnortSnprintfAppend(buf, STD_BUF, "ip=%-17s", buffer);
        ntoa(buffer,80,p->ip_mask);
        SnortSnprintfAppend(buf, STD_BUF, " mask=%-15s", buffer );
    }
    else
    {
        SnortSnprintfAppend(buf, STD_BUF, " count=%-3d", p->count);
        SnortSnprintfAppend(buf, STD_BUF, " seconds=%-3d", p->seconds);
    }
    
    LogMessage("%s\n", buf);
    
    return 1;
}
/*
 * 
 */
int print_thd_local( THD_STRUCT * thd, int type )
{
    SFGHASH  * sfthd_hash; 
    THD_ITEM * sfthd_item;
    THD_NODE * sfthd_node;
    int        gen_id;
    SFGHASH_NODE * item_hash_node;
    int        lcnt=0;
    
    for(gen_id=0;gen_id < THD_MAX_GENID ; gen_id++ )
    {
        sfthd_hash = thd->sfthd_array [ gen_id ];
        if( !sfthd_hash )
        {
            continue;
        }
        
        for(item_hash_node  = sfghash_findfirst( sfthd_hash );
        item_hash_node != 0; 
        item_hash_node  = sfghash_findnext( sfthd_hash ) )
        {
            /* Check for any Permanent sig_id objects for this gen_id */
            sfthd_item = (THD_ITEM*)item_hash_node->data;
            
            /* For each permanent thresholding object, test/add/update the thd object */
            /* We maintain a list of thd objects for each gen_id+sig_id */
            /* each object has it's own unique thd_id */
            
            for( sfthd_node  = (THD_NODE*)sflist_first(sfthd_item->sfthd_node_list);
            sfthd_node != 0;
            sfthd_node = (THD_NODE*)sflist_next(sfthd_item->sfthd_node_list) )
            {
                if (print_thd_node( sfthd_node,type) != 0)
                    lcnt++;
            }
        }
    }
    
    if( ! lcnt ) LogMessage("| none\n");
    
    return 0;
}


/*
 *  Startup Display Of Thresholding
 */
void print_thresholding()
{
    int i, gcnt=0;
    THD_NODE * thd;

    LogMessage("\n");
    LogMessage("+-----------------------[thresholding-config]----------------------------------\n");
    LogMessage("| memory-cap : %d bytes\n",s_memcap);

    LogMessage("+-----------------------[thresholding-global]----------------------------------\n");
    if( !s_thd ) 
    {
        LogMessage("| none\n");
    }
    else
    {
        for(i=0;i<THD_MAX_GENID;i++)
        {
            thd = s_thd->sfthd_garray[i];
            if( !thd ) continue;
            gcnt++;
        }

        if( !gcnt ) 
            LogMessage("| none\n");

        /* display gen_id=global  and sig_id=global rules */
        if( gcnt )
            for(i=0;i<THD_MAX_GENID;i++)
            {
                thd = s_thd->sfthd_garray[i];
                if( !thd ) continue;

                if( thd->gen_id == 0 && thd->sig_id == 0 )
                {
                    print_thd_node( thd, PRINT_GLOBAL );
                    break;
                }
            }

        /* display gen_id!=global and sig_id=global rules */
        if( gcnt )
            for(i=0;i<THD_MAX_GENID;i++)
            {
                thd = s_thd->sfthd_garray[i];
                if( !thd ) continue;

                if( thd->gen_id !=0 ||  thd->sig_id != 0 )
                {
                    print_thd_node( thd, PRINT_GLOBAL );
                }
            }
    }

    LogMessage("+-----------------------[thresholding-local]-----------------------------------\n");
    if( !s_thd )
    {
        LogMessage("| none\n");
    }
    else
    {
        print_thd_local(s_thd, PRINT_LOCAL );
    }

    LogMessage("+-----------------------[suppression]------------------------------------------\n");
    if( !s_thd )
    {
        LogMessage("| none\n");
    }
    else
    {
        print_thd_local(s_thd, PRINT_SUPPRESS );
    }

    LogMessage("-------------------------------------------------------------------------------\n");

}

/*

    Create and Add a Thresholding Event Object

*/
int sfthreshold_create( THDX_STRUCT * thdx  )
{
    if( !s_enabled )
        return 0;

    if( !s_thd )  /* Auto init - memcap must be set 1st, which is not really a problem */
    {
        sfthreshold_init();

        if( !s_thd )
            return -1;
    }

    /* print_thdx( thdx ); */

    /* Add the object to the table - */
    return sfthd_create_threshold( s_thd,
                       thdx->gen_id,
                       thdx->sig_id,
                       thdx->tracking,
                       thdx->type,
                       thdx->priority,
                       thdx->count,
                       thdx->seconds,
                       thdx->ip_address, 
                       thdx->ip_mask,
                       thdx->not_flag ); 
}

/*

    Test an event against the threshold object table
    to determine if it should be logged.

    It will always return the same answer until sfthreshold_reset is
    called

    gen_id:
    sig_id: 
    sip:    host ordered sip
    dip:    host ordered dip
    curtime: 

    2003-05-29 cmg:

     This code is in use in fpLogEvent, CallAlertFuncs, CallLogFuncs
     and the reset function is called in ProcessPacket


    returns 1 - log
            0 - don't log


*/
int sfthreshold_test( unsigned gen_id, unsigned  sig_id, unsigned sip, unsigned dip, long curtime )
{
   if( !s_enabled )
   {
       return 1;
   }
  
   if( !s_thd ) /* this should not happen, see the create fcn */
   {
       return 1;
   }

   if( !s_checked )
   {
      s_checked = 1;
      s_answer  = !sfthd_test_threshold( s_thd, gen_id, sig_id, sip, dip, curtime );
   }
       
   return s_answer;
}

/** 
 * Reset the thresholding system so that subsequent calls to
 * sfthreshold_test will indeed try to alter the thresholding system
 *
 */
void sfthreshold_reset(void)
{
    s_checked = 0;
}
