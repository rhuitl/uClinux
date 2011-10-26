/*!
 *
 * \file sfthd.c  
 *
 * An Abstracted Event Thresholding System
 *
 * Copyright (C) 2003 Sourcefire,Inc.
 * Marc Norton
 *
 * 3/5/07 - man - fixed memory leak in globnal config to limit 
 * of one gid=0, or multiple gid!=0 but not both. 
 * Boris Lytochkin found it.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sflsq.h"
#include "sfghash.h"
#include "sfxhash.h"

#include "sfthd.h"
    
static int s_id = 1;  /* thd_id generator for both local and global thresholds */

/*
 *  Debug Printing
 */

/* #define THD_DEBUG */


/*
 *   This disables adding and testing of Threshold objects
 */
/*
#define CRIPPLE
*/

/*!
  Create a threshold table, initialize the threshold system, 
  and optionally limit it's memory usage.
   
  @param nbytes maximum memory to use for thresholding objects, in bytes.

  @return  THD_STRUCT*
  @retval  0 error
  @retval !0 valid THD_STRUCT
*/
THD_STRUCT * sfthd_new( unsigned nbytes )
{
    THD_STRUCT * thd;
    int          nrows;

    /* Create the THD struct */   
    thd = (THD_STRUCT*) calloc(1,sizeof(THD_STRUCT));
    if( !thd )
    {
        return 0;
    }

    /* Calc max ip nodes for this memory */
    nrows = nbytes /( sizeof(THD_IP_NODE)+sizeof(THD_IP_NODE_KEY) );

#ifndef CRIPPLE 
    /* Create global hash table for all of the IP Nodes */
    thd->ip_nodes = sfxhash_new( nrows,  /* try one node per row - for speed */
                                 sizeof(THD_IP_NODE_KEY), /* keys size */
                                 sizeof(THD_IP_NODE),     /* data size */
                                 nbytes,                  /* memcap **/
                                 1,         /* ANR flag - true ?- Automatic Node Recovery=ANR */
                                 0,         /* ANR callback - none */
                                 0,         /* user freemem callback - none */
                                 1 ) ;      /* Recycle nodes ?*/
    if( !thd->ip_nodes )
    {
#ifdef THD_DEBUG	    
	    printf("Could not allocate the sfxhash table\n");
#endif	    
	    free(thd);
	    return 0;
    }
    
	    
    /* Calc max ip nodes for global thresholding memory */
    nrows = nbytes /( sizeof(THD_IP_GNODE)+sizeof(THD_IP_GNODE_KEY) );

    /* Create global hash table for all of the Global-Thresholding IP Nodes */
    thd->ip_gnodes = sfxhash_new( nrows,  /* try one node per row - for speed */
                                  sizeof(THD_IP_GNODE_KEY), /* keys size */
                                  sizeof(THD_IP_GNODE),     /* data size */
                                  nbytes,                  /* memcap **/
                                  1,         /* ANR flag - true ?- Automatic Node Recovery=ANR */
                                  0,         /* ANR callback - none */
                                  0,         /* user freemem callback - none */
                                  1 ) ;      /* Recycle nodes ?*/
    if( !thd->ip_gnodes )
    {
#ifdef THD_DEBUG	    
	    printf("Could not allocate the sfxhash table\n");
#endif	    
	    free(thd);
	    return 0;
    }


#endif    

    return thd;
}

/*!

Add a permanent threshold object to the threshold table. Multiple
objects may be defined for each gen_id and sig_id pair. Internally
a unique threshold id is generated for each pair.

Threshold objects track the number of events seen during the time
interval specified by seconds. Depending on the type of threshold
object and the count value, the thresholding object determines if
the current event should be logged or dropped.

@param thd Threshold object from sfthd_new()
@param gen_id Generator id
@param sig_id Signauture id
@param tracking Selects tracking by src ip or by dst ip
@param type  Thresholding type: Limit, Threshold, or Limt+Threshold, Suppress  
@param priority Assigns a relative priority to this object, higher numbers imply higher priority

@param count Number of events
@param seconds Time duration over which this threshold object acts.
@param ip      IP address, for supression
@param ip-mask IP mask, applied with ip_mask, for supression

@return integer
@retval  0 successfully added the thresholding object
@retval !0 failed 

*/
static
int 
sfthd_create_threshold_local(	THD_STRUCT * thd,
				unsigned     gen_id,
				unsigned     sig_id,
				int          tracking,
				int          type,
				int          priority,
				int          count,
				int          seconds,
				unsigned     ip_address,
				unsigned     ip_mask,
                unsigned     not_flag)
{
    SFGHASH  * sfthd_hash;
    int        nrows;
    int        hstatus;
    THD_ITEM * sfthd_item;
    THD_NODE * sfthd_node;
    THD_NODE * sfthd_n;
    SF_LNODE * lnode;


    if( !thd )
        return -1;

    if( gen_id >= THD_MAX_GENID )
        return -1;

#ifdef CRIPPLE
    return 0;
#endif    
    
    /* Check for an existing 'gen_id' entry, if none found than create one. */
    if( !thd->sfthd_array[ gen_id ] )
    {
        if( gen_id == 1 )/* patmatch rules gen_id, many rules */
        {
            nrows= THD_GEN_ID_1_ROWS;
        }
        else  /* other gen_id's */
        {
            nrows= THD_GEN_ID_ROWS;
        }

        /* Create the hash table for this gen_id */
        sfthd_hash = sfghash_new( nrows, sizeof(sig_id), 0, 0 );
        if( !sfthd_hash )
        {
            return -2; 
        }

        thd->sfthd_array[gen_id] = sfthd_hash;
    }
    else
    {
        /* Get the hash table for this gen_id */
        sfthd_hash = thd->sfthd_array[gen_id];
    }

    if( !sfthd_hash )
    {
	 return -2;
    }
   
    
    /* Check if sig_id is already in the table - if not allocate it and add it */
    sfthd_item = (THD_ITEM*)sfghash_find( sfthd_hash, (void*)&sig_id );
    if( !sfthd_item )
    {  
        /* Create the sfthd_item hash node data */
        sfthd_item = (THD_ITEM*)calloc(1,sizeof(THD_ITEM));
        if( !sfthd_item )
        {
            return -3;
        }

        sfthd_item->gen_id          = gen_id;
        sfthd_item->sig_id          = sig_id;
        sfthd_item->sfthd_node_list = sflist_new();

        if(!sfthd_item->sfthd_node_list)
        {
            free(sfthd_item);
            return -4;
        }

        /* Add the sfthd_item to the hash table */
        hstatus = sfghash_add( sfthd_hash, (void*)&sig_id, sfthd_item );
        if( hstatus )
        {
            sflist_free(sfthd_item->sfthd_node_list);
            free(sfthd_item);
            return -5;
        }
    }     

    /* 
     * Test that we only have one Limit/Threshold/Both Object at the tail,
     * we can have multiple suppression nodes at the head
     */
    if( sfthd_item->sfthd_node_list->count > 0  )
    {
      THD_NODE * p;
      if( !sfthd_item->sfthd_node_list->tail) 
      {
	      return -10; /* can you say paranoid- if there is a count, there should be a tail */
      }
      p = (THD_NODE*)sfthd_item->sfthd_node_list->tail->ndata;
      if(p) /* just to be safe- if thers a tail, there is is node data */
      {
    	 if( p->type != THD_TYPE_SUPPRESS && type != THD_TYPE_SUPPRESS )
	     {
#ifdef THD_DEBUG
    	     printf("THD_DEBUG: Could not add a 2nd Threshold object, you can onlky have 1 per sid: gid=%u, sid=%u\n",gen_id,sig_id);
#endif	 
    	     return THD_TOO_MANY_THDOBJ;/* cannot add more than one threshold per sid in version 3.0, wait for 3.2 and CIDR blocks */	 
    	 }
      }
    }

    /* Create a THD_NODE for this THD_ITEM (Object) */
    sfthd_node = (THD_NODE*)calloc(1,sizeof(THD_NODE));
    if( !sfthd_node )
    {
        return -6;
    }

    /* Limit priorities to force supression nodes to highest priority */
    if( priority >= THD_PRIORITY_SUPPRESS )
    {
        priority  = THD_PRIORITY_SUPPRESS - 1;
    }

    /* Copy the node parameters */
    sfthd_node->thd_id    = s_id++;   /* produce a unique thd_id for this node */
    sfthd_node->gen_id    = gen_id;   
    sfthd_node->sig_id    = sig_id;   
    sfthd_node->tracking  = tracking; /* by_src, by_dst */
    sfthd_node->type      = type;
    sfthd_node->priority  = priority;
    sfthd_node->count     = count;
    sfthd_node->seconds   = seconds;
    sfthd_node->ip_address= ip_address;
    sfthd_node->ip_mask   = ip_mask;
    sfthd_node->not_flag  = not_flag;
   
    if( type == THD_TYPE_SUPPRESS )
    {
    	sfthd_node->priority = THD_PRIORITY_SUPPRESS;

    	if( sfthd_node->ip_mask == 0 && sfthd_node->ip_address != 0 )
    	{
            sfthd_node->ip_mask = 0xffffffff;
	    }
    }

    thd->count++;

    /*
      If sfthd_node list is empty - add as head node 
    */
    if( !sfthd_item->sfthd_node_list->count )
    {
#ifdef THD_DEBUG
	    printf("Threshold node added to head of list\n");fflush(stdout);
#endif	    
        sflist_add_head(sfthd_item->sfthd_node_list,sfthd_node);
    }

    /*
      else add the sfthd_node using priority to determine where in the list it belongs

      3.0 we can  have only 1 threshold object but several suppression objects plus a 
      single threshold object is ok.  Blocking multiple threshold objects is done above.

      Suppressions have the highest priority and are at the front of the list, the tail node
      is either a supprssion node or the only pure thresholding node.
    */
    else  
    {
        /* Walk the list and insert based on priorities if suppress */
        /* */
        for( lnode = sflist_first_node(sfthd_item->sfthd_node_list); 
             lnode; 
             lnode = sflist_next_node(sfthd_item->sfthd_node_list) )
        {
            sfthd_n = (THD_NODE*)lnode->ndata;

            /* check if the new node is higher priority */
            if( sfthd_node->priority > sfthd_n->priority  )
            {
                /* insert before current node */
#ifdef THD_DEBUG
	    printf("Threshold node added after based on priority\n");fflush(stdout);
#endif	    
                sflist_add_before(sfthd_item->sfthd_node_list,lnode,sfthd_node);
                return 0;
            }

            /* last node, just insert it here */
            if( !lnode->next  ) 
            {
                /* if last node, insert at end of list */
#ifdef THD_DEBUG
	    printf("Threshold node added to tail\n");fflush(stdout);
#endif	    
                sflist_add_tail(sfthd_item->sfthd_node_list,sfthd_node);
                return 0;
            }
        }
    }

    return 0;
}


/*
 *
 *
 */
static
int 
sfthd_create_threshold_global(	THD_STRUCT * thd,
				unsigned     gen_id,
				unsigned     sig_id,
				int          tracking,
				int          type,
				int          priority,
				int          count,
				int          seconds,
				unsigned     ip_address,
				unsigned     ip_mask )
{
    THD_NODE * sfthd_node;
	
    /* 
     * check for duplicates, we only allow 
     * a single gid=0/sid=0 rule,
     * or multiple gid!=0/sid=0 rules 
     */
    if( gen_id == 0)
    {
       int i;
       for(i=0;i<THD_MAX_GENID;i++)
           if( thd->sfthd_garray [ i ] )
           {
               return THD_TOO_MANY_THDOBJ;
           }
    }
    else if(  thd->sfthd_garray [ gen_id ] )
    {
       return THD_TOO_MANY_THDOBJ;
    }

    sfthd_node = (THD_NODE*)calloc(1,sizeof(THD_NODE));
    if( !sfthd_node )
    {
        return -2;
    }

    /* Copy the node parameters */
    sfthd_node->thd_id    = s_id++;   /* produce a unique thd_id for this node */
    sfthd_node->gen_id    = gen_id;   
    sfthd_node->sig_id    = sig_id;  /* -1 for global thresholds */ 
    sfthd_node->tracking  = tracking; /* by_src, by_dst */
    sfthd_node->type      = type;
    sfthd_node->priority  = priority;
    sfthd_node->count     = count;
    sfthd_node->seconds   = seconds;
    sfthd_node->ip_address= ip_address;
    sfthd_node->ip_mask   = ip_mask;
   
    if( sfthd_node->ip_mask == 0 && sfthd_node->ip_address != 0 )
    {
        sfthd_node->ip_mask = 0xffffffff;
    }

    /* need a hash of these where the key=[gen_id,sig_id] => THD_GNODE_KEY, the data = THD_NODE's */
    if( gen_id == 0)/* do em all */
    {
       int i;
       for(i=0;i<THD_MAX_GENID;i++)
           thd->sfthd_garray [ i ] =  sfthd_node;
    }
    else
    { 
       thd->sfthd_garray [ gen_id ] =  sfthd_node;
    }

#ifdef THD_DEBUG
    printf("THD_DEBUG-GLOBAL: created global threshold object for gen_id=%d\n",gen_id);
    fflush(stdout);
#endif    
    
    return 0; 	
}


/*!

Add a permanent threshold object to the threshold table. Multiple
objects may be defined for each gen_id and sig_id pair. Internally
a unique threshold id is generated for each pair.

Threshold objects track the number of events seen during the time
interval specified by seconds. Depending on the type of threshold
object and the count value, the thresholding object determines if
the current event should be logged or dropped.

@param thd Threshold object from sfthd_new()
@param gen_id Generator id
@param sig_id Signauture id
@param tracking Selects tracking by src ip or by dst ip
@param type  Thresholding type: Limit, Threshold, or Limt+Threshold, Suppress  
@param priority Assigns a relative priority to this object, higher numbers imply higher priority

@param count Number of events
@param seconds Time duration over which this threshold object acts.
@param ip      IP address, for supression
@param ip-mask IP mask, applied with ip_mask, for supression

@return integer
@retval  0 successfully added the thresholding object
@retval !0 failed 

 --- Local and Global Thresholding is setup here  ---

*/
int sfthd_create_threshold(	THD_STRUCT * thd,
				unsigned     gen_id,
				unsigned     sig_id,
				int          tracking,
				int          type,
				int          priority,
				int          count,
				int          seconds,
				unsigned     ip_address,
                unsigned     ip_mask,
                unsigned     not_flag)
{

  if( sig_id == 0 )
  {
    	  return  sfthd_create_threshold_global( thd,
				     gen_id,
				     sig_id,
				     tracking,
				     type,
				     priority,
				     count,
				     seconds,
				     ip_address,
				     ip_mask );

  }
  else
  {
      if( gen_id == 0 )
	      return -1;
      
      return  sfthd_create_threshold_local( thd,
                                            gen_id,
                                            sig_id,
                                            tracking,
                                            type,
                                            priority,
                                            count,
                                            seconds,
                                            ip_address,
                                            ip_mask,
                                            not_flag );
  }
}

#ifdef THD_DEBUG
static char * printIP(unsigned u )
{
	static char s[80];
	snprintf(s,80,"%d.%d.%d.%d", (u>>24)&0xff, (u>>16)&0xff, (u>>8)&0xff, u&0xff );
	s[79]=0;
	return s;
}
#endif

/*!
 *
 *  Find/Test/Add an event against a single threshold object.
 *  Events without thresholding objects are automatically loggable.
 *  
 *  @param thd     Threshold table pointer
 *  @param sfthd_node Permanent Thresholding Object
 *  @param sip     Event/Packet Src IP address- should be host ordered for comparison
 *  @param dip     Event/Packet Dst IP address
 *  @param curtime Current Event/Packet time in seconds
 *    
 *  @return  integer
 *  @retval   0 : Event is loggable 
 *  @retval  >0 : Event should not be logged, try next thd object
 *  @retval  <0 : Event should never be logged to this user! Suppressed Event+IP
 *
 */
static
int sfthd_test_object(	THD_STRUCT * thd,
			THD_NODE   * sfthd_node,
			unsigned     sip,   
			unsigned     dip,
			time_t       curtime )  
{
    THD_IP_NODE_KEY key;
    THD_IP_NODE     data,*sfthd_ip_node;
    int             status=0;
    unsigned        ip,dt;

#ifdef THD_DEBUG
        printf("THD_DEBUG: Key THD_NODE IP=%s,",printIP((unsigned)sfthd_node->ip_address) );
        printf(" MASK=%s\n",printIP((unsigned)sfthd_node->ip_mask) );
        printf("THD_DEBUG:        PKT  SIP=%s\n",printIP((unsigned)sip) );
        printf("THD_DEBUG:        PKT  DIP=%s\n",printIP((unsigned)dip) );
	fflush(stdout);
#endif

    /*
     *  Get The correct IP  
     */
    if( sfthd_node->tracking== THD_TRK_SRC ) 
    {
       ip = sip;
    }
    else
    {
       ip = dip;
    }
    
    /*
     *  Check for and test Suppression of this event to this IP 
     */
    if( sfthd_node->type == THD_TYPE_SUPPRESS )
    {
#ifdef THD_DEBUG
        printf("THD_DEBUG: SUPPRESS NODE Testing...\n");fflush(stdout);
#endif
        if((sfthd_node->ip_address == (sfthd_node->ip_mask & ip) && !sfthd_node->not_flag) ||
           (sfthd_node->ip_address != (sfthd_node->ip_mask & ip) && sfthd_node->not_flag))
        { 
#ifdef THD_DEBUG
            printf("THD_DEBUG: SUPPRESS NODE, do not log events with this IP\n");fflush(stdout);
#endif
            return -1; /* Don't log, and stop looking( event's to this address for this gen_id+sig_id) */
        }
        return 1; /* Keep looking for other suppressors */
    }

    /*
    *  Go on and do standard thresholding
    */
    
    /* Set up the key */
    key.ip     = ip;
    key.thd_id = sfthd_node->thd_id;

    /* Set up a new data element */
    data.ip     = ip;
    data.count  = 1;
    data.tstart = curtime; /* Event time */

    /* 
     * Check for any Permanent sig_id objects for this gen_id  or add this one ...
     */
    status = sfxhash_add( thd->ip_nodes, (void*)&key, &data );
    
    if( status == SFXHASH_INTABLE )
    {
        /* Already in the table */
        sfthd_ip_node = thd->ip_nodes->cnode->data;

        /* Increment the event count */
        sfthd_ip_node->count++;
    }
    else if (status )
    {
        /* hash error */
        return 1; /*  check the next threshold object */
    }
    else
    {
        /* Was not in the table - it was added - work with our copy of the data */
        sfthd_ip_node = &data;
    }


    /*
     *  Do the appropriate test for the Threshold Object Type 
     */
    
    /*
      Limit
    */
    if( sfthd_node->type == THD_TYPE_LIMIT )
    {
#ifdef THD_DEBUG
        printf("\n...Limit Test\n");
	fflush(stdout);
#endif		
        dt = curtime - sfthd_ip_node->tstart;
        if( dt > sfthd_node->seconds )
        {   /* reset */
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;
        }

#ifdef THD_DEBUG
        printf("...dt=%d, sfthd_node->seconds=%d\n",dt,sfthd_node->seconds );
        printf("...sfthd_ip_node->count=%d, sfthd_node->count=%d\n",sfthd_ip_node->count,sfthd_node->count );
	fflush(stdout);
#endif
        if( sfthd_ip_node->count <= sfthd_node->count )
        {
            return 0; /* Log it, stop looking: only log the 1st 'count' events */
        }

        return -1; /* Don't Log yet, don't keep looking : already logged our limit, don't log this sid  */
    }
    
    else if( sfthd_node->type == THD_TYPE_THRESHOLD )
    {
#ifdef THD_DEBUG
        printf("\n...Threshold Test\n");
	fflush(stdout);
#endif		
        dt = curtime - sfthd_ip_node->tstart;
	if( dt > sfthd_node->seconds )
        {
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;

            return -1; /* Don't Log, keep looking: only log after we reach count, which must be > '1' */
        }
        else
        {
            if( sfthd_ip_node->count >= sfthd_node->count ) 
            {
                /* reset */
                sfthd_ip_node->count = 0;
                sfthd_ip_node->tstart= curtime;
			
                return 0; /* Log it, stop looking */ 
            }
            return -1; /* don't log yet */
        }
    }

    else if( sfthd_node->type == THD_TYPE_BOTH )
    {
#ifdef THD_DEBUG
        printf("\n...Threshold+Limit Test\n");
	fflush(stdout);
#endif
        dt = curtime - sfthd_ip_node->tstart;
        if( dt > sfthd_node->seconds )
        {
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;

            return -1; /* Don't Log yet, keep looking: only log after we reach count, which must be > '1' */
        }
        else
        {
            if( sfthd_ip_node->count >= sfthd_node->count ) 
            {
                if( sfthd_ip_node->count >  sfthd_node->count ) 
		{
                    return -1; /* don't log it, stop  looking, log once per time interval - than block it */
		}
                return 0; /* Log it, stop looking, log the 1st event we see past 'count' events */
            }
	    else  /* Block it from logging */
	    {
              return -1; /* don't log it, stop  looking,  we must see at least count events 1st */
	    }
        }
    }

#ifdef THD_DEBUG
        printf("THD_DEBUG: You should not be here...\n");
	fflush(stdout);
#endif

    	return 0;  /* should not get here, so log it just to be safe */
}
/*
 *
 *
 *
 *   Test a global thresholding object 
 *
 * 
 *   
 */ 
static
int sfthd_test_gobject(	THD_STRUCT * thd,
			THD_NODE   * sfthd_node,  
			unsigned     gen_id,     /* from current event */
			unsigned     sig_id,     /* from current event */
			unsigned     sip,        /* " */
			unsigned     dip,        /* " */
			time_t       curtime )   
{
    THD_IP_GNODE_KEY key;
    THD_IP_GNODE     data, *sfthd_ip_node;
    int              status=0;
    unsigned         ip, dt;

#ifdef THD_DEBUG
        printf("THD_DEBUG-GLOBAL:  gen_id=%u, sig_id=%u\n",gen_id,sig_id);
        printf("THD_DEBUG: Global THD_NODE IP=%s,",printIP((unsigned)sfthd_node->ip_address) );
        printf(" MASK=%s\n",printIP((unsigned)sfthd_node->ip_mask) );
        printf("THD_DEBUG:        PKT  SIP=%s\n",printIP((unsigned)sip) );
        printf("THD_DEBUG:        PKT  DIP=%s\n",printIP((unsigned)dip) );
	fflush(stdout);
#endif

    /*
     *  Get The correct IP  
     */
    if( sfthd_node->tracking== THD_TRK_SRC ) 
    {
       ip = sip;
    }
    else
    {
       ip = dip;
    }
    
    /*
     *  Check for and test Suppression of this event to this IP 
     */
    if( sfthd_node->type == THD_TYPE_SUPPRESS )
    {
#ifdef THD_DEBUG
        printf("THD_DEBUG: G-SUPPRESS NODE Testing...\n");fflush(stdout);
#endif
        if( sfthd_node->ip_address == (sfthd_node->ip_mask & ip) )
	{ 
#ifdef THD_DEBUG
            printf("THD_DEBUG: G-SUPPRESS NODE, do not log events with this IP\n");fflush(stdout);
#endif
            return -1; /* Don't log, and stop looking( event's to this address for this gen_id+sig_id) */
        }
	return 1; /* Keep looking for other suppressors */
    }

    /*
    *  Go on and do standard thresholding
    */
    
    /* Set up the key */
    key.ip     = ip;
    key.gen_id = sfthd_node->gen_id;
    key.sig_id = sig_id;

    /* Set up a new data element */
    data.count  = 1;
    data.tstart = curtime; /* Event time */

    /* 
     * Check for any Permanent sig_id objects for this gen_id  or add this one ...
     */
    status = sfxhash_add( thd->ip_gnodes, (void*)&key, &data );
    
    if( status == SFXHASH_INTABLE )
    {
        /* Already in the table */
        sfthd_ip_node = thd->ip_gnodes->cnode->data;

        /* Increment the event count */
        sfthd_ip_node->count++;
    }
    else if (status )
    {
        /* hash error */
        return 1; /*  check the next threshold object */
    }
    else
    {
        /* Was not in the table - it was added - work with our copy of the data */
        sfthd_ip_node = &data;
    }


    /*
     *  Do the appropriate test for the Threshold Object Type 
     */
    
    /*
      Limit
    */
    if( sfthd_node->type == THD_TYPE_LIMIT )
    {
#ifdef THD_DEBUG
        printf("\n...Limit Test\n");
	fflush(stdout);
#endif		
        dt = curtime - sfthd_ip_node->tstart;
        if( dt > sfthd_node->seconds )
        {   /* reset */
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;
        }

#ifdef THD_DEBUG
        printf("...dt=%d, sfthd_node->seconds=%d\n",dt, sfthd_node->seconds );
        printf("...sfthd_ip_node->count=%d, sfthd_node->count=%d\n",sfthd_ip_node->count,sfthd_node->count );
	fflush(stdout);
#endif
        if( sfthd_ip_node->count <= sfthd_node->count )
        {
            return 0; /* Log it, stop looking: only log the 1st 'count' events */
        }

        return -1; /* Don't Log yet, don't keep looking : already logged our limit, don't log this sid  */
    }
    
    else if( sfthd_node->type == THD_TYPE_THRESHOLD )
    {
#ifdef THD_DEBUG
        printf("\n...Threshold Test\n");
	fflush(stdout);
#endif		
        dt = curtime - sfthd_ip_node->tstart;
	if( dt > sfthd_node->seconds )
        {
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;

            return -1; /* Don't Log, keep looking: only log after we reach count, which must be > '1' */
        }
        else
        {
            if( sfthd_ip_node->count >= sfthd_node->count ) 
            {
                /* reset */
                sfthd_ip_node->count = 0;
                sfthd_ip_node->tstart= curtime;
			
                return 0; /* Log it, stop looking */ 
            }
            return -1; /* don't log yet */
        }
    }

    else if( sfthd_node->type == THD_TYPE_BOTH )
    {
#ifdef THD_DEBUG
        printf("\n...Threshold+Limit Test\n");
	fflush(stdout);
#endif
        dt = curtime - sfthd_ip_node->tstart;
        if( dt > sfthd_node->seconds )
        {
            sfthd_ip_node->tstart = curtime;
            sfthd_ip_node->count  = 1;

            return -1; /* Don't Log yet, keep looking: only log after we reach count, which must be > '1' */
        }
        else
        {
            if( sfthd_ip_node->count >= sfthd_node->count ) 
            {
                if( sfthd_ip_node->count >  sfthd_node->count ) 
		{
                    return -1; /* don't log it, stop  looking, log once per time interval - than block it */
		}
                return 0; /* Log it, stop looking, log the 1st event we see past 'count' events */
            }
	    else  /* Block it from logging */
	    {
              return -1; /* don't log it, stop  looking,  we must see at least count events 1st */
	    }
        }
    }

#ifdef THD_DEBUG
        printf("THD_DEBUG: You should not be here...\n");
	fflush(stdout);
#endif

    	return 0;  /* should not get here, so log it just to be safe */
}


/*!
 *
 *  Test a an event against the threshold database.  
 *  Events without thresholding objects are automatically 
 *  loggable.
 *  
 *  @param thd     Threshold table pointer
 *  @param gen_id  Generator Id from the event
 *  @param sig_id  Signature Id from the event
 *  @param sip     Event/Packet Src IP address
 *  @param dip     Event/Packet Dst IP address
 *  @param curtime Current Event/Packet time
 *    
 *  @return  integer
 *  @retval  0 : Event is loggable 
 *  @retval !0 : Event should not be logged
 *
 */
int sfthd_test_threshold( THD_STRUCT * thd,
                          unsigned gen_id,  
                          unsigned sig_id,
                          unsigned sip,   
                          unsigned dip,
                          long     curtime )  
{
    SFGHASH  * sfthd_hash; 
    THD_ITEM * sfthd_item;
    THD_NODE * sfthd_node, * g_thd_node;
    int cnt;
    int status=0;

#ifdef CRIPPLE
    return 0;
#endif

#ifdef THD_DEBUG
    printf("sfthd_test_threshold...\n");fflush(stdout);
#endif    
    if( gen_id >= THD_MAX_GENID )
    {
#ifdef THD_DEBUG
        printf("THD_DEBUG: invalid gen_id=%u\n",gen_id);
	fflush(stdout);
#endif  
	return 0; /* bogus gen_id */
    }

    /*
     *  Get the hash table for this gen_id
     */
    sfthd_hash = thd->sfthd_array [ gen_id ];
    if( !sfthd_hash )
    {
#ifdef THD_DEBUG
        printf("THD_DEBUG: no hash table entry for gen_id=%u\n",gen_id);
	fflush(stdout);
#endif      
        goto global_test;	
        /* return 0; */ /* no threshold objects for this gen_id, log it ! */
    }

    /* 
     * Check for any Permanent sig_id objects for this gen_id 
     */
    sfthd_item = (THD_ITEM*)sfghash_find( sfthd_hash, (void*)&sig_id );
    if( !sfthd_item )
    {
#ifdef THD_DEBUG
        printf("THD_DEBUG: no THD objects for gen_id=%u, sig_id=%u\n",gen_id,sig_id);
	fflush(stdout);
#endif       
        goto global_test;	
        /* return 0; */ /* no matching permanent sig_id objects so, log it ! */
    }
   
    /* No List of Threshold objects - bail and log it */ 
    if( !sfthd_item->sfthd_node_list )
    {
          goto global_test;	
	  /*  return 0; */
    }
		    
    /* For each permanent thresholding object, test/add/update the thd object */
    /* We maintain a list of thd objects for each gen_id+sig_id */
    /* each object has it's own unique thd_id */
    /* Suppression nodes have a very high priority, so they are tested 1st */
    cnt=0;
    for( sfthd_node  = (THD_NODE*)sflist_first(sfthd_item->sfthd_node_list);
         sfthd_node != 0;
         sfthd_node  = (THD_NODE*)sflist_next(sfthd_item->sfthd_node_list) )
    {
        cnt++;
	
#ifdef THD_DEBUG
        printf("THD_DEBUG: gen_id=%u sig_id=%u testing thd_id=%d thd_type=%d\n",
			gen_id, sig_id, sfthd_node->thd_id, sfthd_node->type);
	fflush(stdout);
#endif
	/*
	 *   Test SUPPRESSION and THRESHOLDING
	 *
	 *   For 3.0 SUPPRESSION returns -1 to suppress, +1 to keep on testing the next object
	 *           THRESHOLDING returns -1 to suppress, and 0 to log
	 */
        status = sfthd_test_object( thd, sfthd_node, sip, dip, curtime );
	
        if( status < 0 ) /* -1 == Don't log and stop looking */
        {
#ifdef THD_DEBUG
		printf("THD_DEBUG: gen_id=%u sig_id=%u, UnLoggable\n\n",gen_id, sig_id,cnt);
		fflush(stdout);
#endif
		return 1;  /* 1 == Don't log it*/
        }
        else if( status == 0 )  /* Log it and stop looking */
        {
#ifdef THD_DEBUG
		printf("THD_DEBUG: gen_id=%u sig_id=%u tested %d THD_NODE's, Loggable\n\n",sfthd_item->gen_id, sfthd_item->sig_id,cnt);
		fflush(stdout);
#endif
		return 0; /* 0 == Log the event */
        }
        /* status > 0 : Log it later but Keep looking....check the next threshold object for a blocking action ... 
	*              For 3.0 SUPPRESS objects return +1 if they don't suppress... so we can fall out of this loop
	*              to log by returning 0 below....
	*/
    }


    /*
     * 
     * 
     *  Test for a global threshold object  - we're here cause ther were no threshold objects for this gen_id/sig_id pair
     *
     *  
     */
global_test:

#ifdef THD_DEBUG
    printf("THD_DEBUG-GLOBAL: doing global object test\n");
#endif    
     
     g_thd_node = thd->sfthd_garray[ gen_id ];
     if( g_thd_node )
     {
         status = sfthd_test_gobject( thd, g_thd_node, gen_id, sig_id, sip, dip, curtime );
         if( status < 0 ) /* -1 == Don't log and stop looking */
         {
#ifdef THD_DEBUG
            printf("THD_DEBUG-GLOBAL: gen_id=%u sig_id=%u THD_NODE's, UnLoggable\n\n",gen_id, sig_id);
	    fflush(stdout);
#endif
            return 1;  /* 1 == Don't log it*/
         }

	 /* Log it ! */
#ifdef THD_DEBUG
        printf("THD_DEBUG-GLOBAL: gen_id=%u sig_id=%u  THD_NODE's, Loggable\n\n",gen_id, sig_id);
        fflush(stdout);
#endif
     }
     else
     {
#ifdef THD_DEBUG
        printf("THD_DEBUG-GLOBAL: no Global THD Object for gen_id=%u, sig_id=%u\n\n",gen_id, sig_id);
        fflush(stdout);
#endif
     }
     
    return 0; /* Default: Log it if we did not block the logging action */
}

/*!
 *   A function to print the thresholding objects to stdout.
 *
 */
int sfthd_show_objects( THD_STRUCT * thd )
{
    SFGHASH  * sfthd_hash; 
    THD_ITEM * sfthd_item;
    THD_NODE * sfthd_node;
    int        gen_id;
    SFGHASH_NODE * item_hash_node;

    for(gen_id=0;gen_id < THD_MAX_GENID ; gen_id++ )
    {
        sfthd_hash = thd->sfthd_array [ gen_id ];
        if( !sfthd_hash )
        {
            continue;
        }

        printf("...GEN_ID = %u\n",gen_id);

        for(item_hash_node  = sfghash_findfirst( sfthd_hash );
            item_hash_node != 0; 
            item_hash_node  = sfghash_findnext( sfthd_hash ) )
        {
            /* Check for any Permanent sig_id objects for this gen_id */
            sfthd_item = (THD_ITEM*)item_hash_node->data;

            printf(".....GEN_ID = %u, SIG_ID = %u\n",gen_id,sfthd_item->sig_id);
     
            /* For each permanent thresholding object, test/add/update the thd object */
            /* We maintain a list of thd objects for each gen_id+sig_id */
            /* each object has it's own unique thd_id */

            for( sfthd_node  = (THD_NODE*)sflist_first(sfthd_item->sfthd_node_list);
                 sfthd_node != 0;
                 sfthd_node = (THD_NODE*)sflist_next(sfthd_item->sfthd_node_list) )
            {
                printf(".........THD_ID  =%d\n",sfthd_node->thd_id );
               
	       	if( sfthd_node->type == THD_TYPE_SUPPRESS )
                printf(".........type    =Suppress\n");
                if( sfthd_node->type == THD_TYPE_LIMIT )
                printf(".........type    =Limit\n");
                if( sfthd_node->type == THD_TYPE_THRESHOLD )
                printf(".........type    =Threshold\n");
                if( sfthd_node->type == THD_TYPE_BOTH )
                printf(".........type    =Both\n");
		
                printf(".........tracking=%d\n",sfthd_node->tracking);
                printf(".........priority=%d\n",sfthd_node->priority);
		  
                if( sfthd_node->type == THD_TYPE_SUPPRESS )
                {
                    printf(".........ip      =%d\n",sfthd_node->ip_address);
                    printf(".........mask    =%d\n",sfthd_node->ip_mask);
                    printf(".........not_flag=%d\n",sfthd_node->ip_mask);
                }
                else
                {
		    printf(".........count   =%d\n",sfthd_node->count);
		    printf(".........seconds =%d\n",sfthd_node->seconds);
                }
            }
	}
    }

    return 0;
}

