/*!
    \file sfthd.h
*/
#ifndef _SF_THRESHOLDING_
#define _SF_THRESHOLDING_

#include "sflsq.h"

#include "sfghash.h"
#include "sfxhash.h"
/*!
    Max GEN_ID value - Set this to the Max Used by Snort, this is used for the
    dimensions of the gen_id lookup array.  
	
	Rows in each hash table, by gen_id.
*/
#define THD_MAX_GENID     8129
#define THD_GEN_ID_1_ROWS 4096
#define THD_GEN_ID_ROWS   512

#define THD_TOO_MANY_THDOBJ -15 

/*!
   Type of Thresholding
*/
enum 
{
  THD_TYPE_LIMIT,
  THD_TYPE_THRESHOLD,
  THD_TYPE_BOTH,
  THD_TYPE_SUPPRESS,
};

/*
   Very high priority for suppression objects 
   users priorities are limited to this minus one  
*/
#define THD_PRIORITY_SUPPRESS 1000000

/*!
   Tracking by src, or by dst
*/
enum
{
  THD_TRK_SRC,
  THD_TRK_DST,
};


/*!
    THD_IP_NODE

    Dynamic hashed node data - added and deleted during runtime
    These are added during run-time, and recycled if we max out memory usage.
*/
typedef struct {
 
 unsigned ip;
 unsigned count;
 time_t   tstart;

}THD_IP_NODE;


typedef struct {
 
 unsigned count;
 time_t   tstart;

}THD_IP_GNODE;

/*!
    THD_IP_NODE_KEY

    HASH Key to lookup and store Ip nodes
*/
typedef struct{

  int      thd_id;
  unsigned ip;

} THD_IP_NODE_KEY ;

typedef struct{

  unsigned gen_id;
  unsigned sig_id;
  unsigned ip;

} THD_IP_GNODE_KEY ;


/*!
    THD_NODE

    A Thresholding Object
    These are created at program startup, and remain static. 
	The THD_IP_NODE elements are dynamic.
*/
typedef struct {
 
 int      thd_id;  /* Id of this node */

 unsigned gen_id; /* Keep these around if needed */
 unsigned sig_id;
 int      tracking; /* by_src, by_dst */
 int      type;
 int      priority;
 unsigned count;
 unsigned seconds;

 unsigned ip_address;
 unsigned ip_mask;

 unsigned not_flag; /* 0=not netgated, 1=negated */

}THD_NODE;


/*!
    THD_ITEM

    The THD_ITEM acts as a container of gen_id+sig_id based threshold objects,
    this allows multiple threshold objects to be applied to a single 
    gen_id+sig_id pair. The sflist is created using the priority field, 
    so highest priority objects are first in the list. When processing the 
    highest priority object will trigger first.  

    These are static data elements, built at program startup.
*/
typedef struct {

 unsigned   gen_id; /* just so we know what gen_id we are */
 unsigned   sig_id; 
 /*
   List of THD_NODE's - walk this list and hash the 'THD_NODE->sfthd_id + src_ip or dst_ip'
   to get the correct THD_IP_NODE.
 */
 SF_LIST  * sfthd_node_list;
 
}THD_ITEM;


/*
*  Temporary structure usefule when parsing the Snort rules
*/
typedef struct {
  unsigned gen_id;
  unsigned sig_id;
  int  type;
  int  tracking;
  int  priority;
  int  count;
  int  seconds;
  int  ip_address;
  int  ip_mask;
  unsigned not_flag;
}THDX_STRUCT;


/*!
    THD_STRUCT 

    The main thresholding data structure. 

    Local and global threshold thd_id's are all unqiue, so we use just one ip_nodes lookup table
 */
typedef struct {

 SFGHASH  * sfthd_array [THD_MAX_GENID]; /* Local Hash of THD_ITEM nodes,  lookup by key=sig_id */

 THD_NODE * sfthd_garray[THD_MAX_GENID]; /* Global array of THD_NODE nodes,lookup by key=gen_id  */

 SFXHASH  * ip_nodes;  /* Global hash of active IP's key=THD_IP_NODE_KEY, data=THD_IP_NODE */

 int        count;

 SFXHASH  * ip_gnodes;  /* Global hash of active IP's key=THD_IP_GNODE_KEY, data=THD_IP_GNODE */

 SFXHASH  * supress;    /* Global hash of supressed nodes */

					 
}THD_STRUCT;


/*
 * Prototypes 
 */
THD_STRUCT * sfthd_new( unsigned nbytes );

int sfthd_create_threshold( THD_STRUCT * thd,
                       unsigned     gen_id,
                       unsigned     sig_id,
                       int          tracking,
                       int          type,
                       int          priority,
                       int          count,
                       int          seconds,
                       unsigned     ip_address, 
                       unsigned     ip_mask, 
                       unsigned     not_flag ); 

int sfthd_test_threshold( THD_STRUCT * thd,
                        unsigned     gen_id,  
                        unsigned     sig_id,
                        unsigned     sip,   
                        unsigned     dip,
			long         curtime ) ;

int sfthd_show_objects( THD_STRUCT * thd );

#endif
