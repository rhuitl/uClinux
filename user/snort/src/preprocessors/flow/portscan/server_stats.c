/**
 * @file   server_stats.c
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 13 14:28:50 2003
 * 
 * @brief  "policy" learning portion of portscan detector
 * 
 * This keeps a table of (dip+dport+dprotocol) -> count to help
 * identify what is a normal looking portscan versus what is pretty
 * far outta whack.
 *
 */

#include "server_stats.h"
#include "flowps.h"
#include "sfxhash.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h> 
#include <string.h>

static void server_stats_init_entry(void);

typedef struct _SERVER_KEY
{
    u_int32_t address;
    u_int32_t port;
    u_int32_t protocol;  
} SERVER_KEY;

static SERVER_KEY s_key; 
static int s_debug = 0;

/** 
 * Print out the entirety of the server cache.
 * 
 * @param ssp server stats pointer
 */
void server_stats_dump(SERVER_STATS *ssp)
{
    SFXHASH_NODE *nodep;
    
    if(ssp && ssp->ipv4_table)
    {
        for( nodep = sfxhash_ghead(ssp->ipv4_table);
             nodep != NULL;
             nodep = sfxhash_gnext(nodep) )
        {
            SERVER_KEY *kp = (SERVER_KEY *) nodep->key;
            u_int32_t count = *(u_int32_t *) nodep->data;
            
            flow_printf("hits: %u proto: %3u port: %5u ip: %s\n",
                        count,
                        kp->protocol,
                        kp->port,
                        inet_ntoa(*(struct in_addr *)&kp->address));
        }
    }
    else
    {
        flow_printf("nothing to dump!\n");
    }
}

void server_stats(SERVER_STATS *ssp, int dumpall)
{
    unsigned total, fail, success, nodes, anr, overhead, memcap;

    memcap = overhead = nodes = anr = total = fail = success = 0;
    
    if(ssp && ssp->ipv4_table)
    {
        total    = sfxhash_find_total(ssp->ipv4_table);
        fail     = sfxhash_find_fail(ssp->ipv4_table);
        success  = sfxhash_find_success(ssp->ipv4_table);
        nodes    = sfxhash_count(ssp->ipv4_table);
        anr      = sfxhash_anr_count(ssp->ipv4_table);
        memcap   = server_stats_memcap(ssp);
        overhead = server_stats_overhead_bytes(ssp);
    }    

    flow_printf(",-----[SERVER STATS]------------\n");
    flow_printf("   Memcap: %u  Overhead Bytes: %u\n",
                memcap, overhead);
    
    flow_printf("   Finds: %u (Sucessful: %u(%%%lf) Unsucessful: %u(%%%lf))\n",
                total,
                success, calc_percent(success,total),
                fail, calc_percent(fail,total));

    flow_printf("   Nodes: %u\n", nodes);
    
    flow_printf("   Recovered Nodes: %u\n", anr);
    flow_printf("`-------------------------------\n");

    if(dumpall)
        server_stats_dump(ssp);
}

/** 
 * Initialize the server stats structure
 *
 * If we do not specify a watchnet, then we have no use for this
 * structure
 * 
 * @param ssp server stats structure to initialize
 * @param watchnet what network we're watching for information
 * @param rows how many rows the underlying table should use
 * @param memcap what our total memory limit is
 * 
 * @return FLOW_SUCCESS on success
 */
int server_stats_init(SERVER_STATS *ssp, IPSET *watchnetv4,
                      unsigned int rows, int memcap)
{
    if(!ssp || !watchnetv4)
        return FLOW_ENULL;

    server_stats_init_entry();
    
    memset(ssp, 0, sizeof(SERVER_STATS));

    
    if(ipset_family(watchnetv4) != IPV4_FAMILY)
    {
        return FLOW_EINVALID;
    }

    /* what size should we do? */
    ssp->ipv4_table = sfxhash_new(rows,               /* # of rows in HT*/
                                  sizeof(SERVER_KEY), /* size of the key  */
                                  sizeof(u_int32_t),   /* data size */
                                  memcap,            /* how much memory is alloted */
                                  1,                 /* auto recover nodes */
                                  NULL,              /* autorecovery function */
                                  NULL,              /* free function for the data */
                                  1);                /* recycle old nodes */

    if(ssp->ipv4_table == NULL)
    {
        return FLOW_ENOMEM;
    }

    ssp->ipv4_watch = ipset_copy(watchnetv4);
    
    if(!ssp->ipv4_watch)
    {
        sfxhash_delete(ssp->ipv4_table);        
        return FLOW_ENOMEM;
    }

    return FLOW_SUCCESS;
}

int server_stats_destroy(SERVER_STATS *ssp)
{
    if(!ssp)
    {
        return FLOW_ENULL;
    }
    
    sfxhash_delete(ssp->ipv4_table);
    ipset_free(ssp->ipv4_watch);

    return FLOW_SUCCESS;
}

/** 
 * See if we are watching this particular IP 
 * 
 * @param ssp server stats pointer
 * @param address ipv4 address in NETWORK BYTE ORDER
 * 
 * @return 1 if this SERVER_STATS is watching this network
 */
int server_stats_contains(SERVER_STATS *ssp, u_int32_t address)
{
    if(ssp->ipv4_watch)
    {
        u_int32_t hostaddress = ntohl(address);

        if(ipset_contains(ssp->ipv4_watch, &hostaddress, NULL, IPV4_FAMILY))
        {
            return FLOW_SUCCESS;
        }
    }
    
    return FLOW_DISABLED;        
}


u_int32_t server_stats_hitcount_ipv4(SERVER_STATS *ssp, u_int8_t ip_proto, u_int32_t address, u_int16_t port)
{
    SERVER_KEY *kp = &s_key;
    u_int32_t *hitcountp;
#ifdef DEBUG
    u_int32_t hostaddress = ntohl(address);
#endif /* DEBUG */

    /* OK, IPSETs are acting in HOST ORDER */
    FLOWASSERT(ipset_contains(ssp->ipv4_watch, &hostaddress, NULL, IPV4_FAMILY));

    /* make a key */
    kp->address = address;
    kp->port = port;
    kp->protocol = ip_proto;
    
    hitcountp = (u_int32_t *) sfxhash_find(ssp->ipv4_table, kp);
    
    if(hitcountp != NULL)
    {
        return *hitcountp;
    }

    return 0;    
}

int server_stats_add_ipv4(SERVER_STATS *ssp, u_int8_t ip_proto, u_int32_t address, u_int16_t port,
                          u_int32_t *retcount)
{
    SERVER_KEY *kp = &s_key;
    u_int32_t one = 1;
    u_int32_t *hitcountp = NULL;
    int ret;
#ifdef DEBUG
    u_int32_t hostaddress = ntohl(address);
#endif /* DEBUG */
    
    if(ssp == NULL || retcount == NULL)
        return FLOW_ENULL;

    /* calls to this subsystem should only be made if we are really watching this. */
    FLOWASSERT(ipset_contains(ssp->ipv4_watch, &hostaddress, NULL, IPV4_FAMILY));
    
    /* make the key */
    kp->address  = address;
    kp->port     = port;
    kp->protocol = ip_proto;
    
    /* find the key, add 1 to it or add a new node to the table */
    ret = sfxhash_add(ssp->ipv4_table, kp, &one);
    
    switch(ret)
    {
    case SFXHASH_NOMEM:
        /* NOMEM means that we would add it if we could but we're
         *  hard-core out of space.  So, just assume we added it.
         */
    case SFXHASH_OK:
        *retcount = 1;        
        break;
    case SFXHASH_INTABLE:
        hitcountp = (u_int32_t *) sfxhash_mru(ssp->ipv4_table);
        
        /* never let us wrap around to less hits */
        if(!hitcountp)
        {
            /* this is an odd error! */
            return FLOW_BADJUJU;
        }
        else
        {
            if((*hitcountp) < SERVER_STATS_MAX_HITCOUNT)
            {
                (*hitcountp)++;
            }            
        }
        break;
    }
    
    return FLOW_SUCCESS;
}

int server_stats_remove_ipv4(SERVER_STATS *ssp, u_int8_t ip_proto,
                             u_int32_t address, u_int16_t port)
{
    SERVER_KEY *kp = &s_key;

    if(!ssp)
        return FLOW_ENULL;
       
    kp->address = address;
    kp->port = port;
    kp->protocol = ip_proto;

    /* not like we can do anything if this failed */
    sfxhash_remove(ssp->ipv4_table, kp);

    return FLOW_SUCCESS;
}


/* start of parsing helpers */
#define FAMILY_SIZE     1
#define FAMILY_OFFSET   0

#define IPV4_SIZE       4
#define IPV4_OFFSET     (FAMILY_SIZE)

#define PORT_SIZE       2
#define PORT_OFFSET     (IPV4_OFFSET + IPV4_SIZE)

#define IP_PROTO_SIZE   1
#define IP_PROTO_OFFSET (PORT_OFFSET + PORT_SIZE)

#define COUNT_SIZE      4
#define COUNT_OFFSET    (IP_PROTO_OFFSET + IP_PROTO_SIZE)

#define STATSREC_SIZE (FAMILY_SIZE + IPV4_SIZE + PORT_SIZE + IP_PROTO_SIZE + COUNT_SIZE)
/* end parsing helpers */

int server_stats_save(SERVER_STATS *ssp, char *filename)
{
    SFXHASH_NODE *nodep;
    unsigned char buf[STATSREC_SIZE];
    int fd;
    
    if(!filename || !ssp)
        return FLOW_ENULL;
#ifndef O_SYNC
#define O_SYNC O_FSYNC
#endif

    /* open this description, create it if necessary, always wait on
     * sync to disk w/ every write, only write */
    fd = open(filename, O_CREAT|O_TRUNC|O_SYNC|O_WRONLY);

    if(fd < 0)
    {
        if(s_debug)
        {
            flow_printf("%s was not found\n", filename);
        }
        return FLOW_NOTFOUND;
    }

    /* this is a crappy parser... that's par for the course */
    for( nodep = sfxhash_ghead(ssp->ipv4_table);
         nodep != NULL;
         nodep = sfxhash_gnext(nodep) )
    {
        SERVER_KEY *kp = (SERVER_KEY *) nodep->key;
        u_int32_t count = *(u_int32_t *) nodep->data;
        u_int8_t  family = '4';
        u_int32_t ipv4_address;
        u_int16_t port;
        u_int8_t  protocol;
        ssize_t  wbytes = 0;
        ssize_t wsize;
            
        
        count        = ntohl(count);       
        ipv4_address = htonl(kp->address);
        port         = htons((u_int16_t) kp->port);
        protocol     = (u_int8_t) kp->protocol;

        memcpy(buf + FAMILY_OFFSET,   &family,        FAMILY_SIZE);
        memcpy(buf + IPV4_OFFSET,     &ipv4_address,  IPV4_SIZE);       
        memcpy(buf + PORT_OFFSET,     &port,          PORT_SIZE);
        memcpy(buf + IP_PROTO_OFFSET, &protocol,      IP_PROTO_SIZE);
        memcpy(buf + COUNT_OFFSET,    &count,         COUNT_SIZE);

        /* now make sure we get a full record on disk */
        while(wbytes < STATSREC_SIZE)
        {
            /* write the number of bytes we already have - the #
             * already written */
            wsize = write(fd, buf, (STATSREC_SIZE - wbytes));

            if(wsize < 0)
            {
                /* this record was truncated */
                flow_printf("Truncated Server Record!\n");
                return FLOW_EINVALID;
            }
            else
            {
                wbytes += wsize;
            }
        }
    }
    
    return FLOW_SUCCESS;
}


/** 
 * initialize the static s_init_key variable once and only once.This
 * is used to zero out the key so that if the compiler pads the
 * structure, we still have 0's in this keylookup.
 * 
 */
static void server_stats_init_entry(void)
{
    static int init_once = 1;

    if(init_once)
    {
        init_once = 0;
        memset(&s_key, 0, sizeof(SERVER_KEY));
    }
}


/** 
 * get the memcap
 * 
 * @param sbp server_stats ptr to return the memcap of
 * 
 * @return memcap or -1
 */
int server_stats_memcap(SERVER_STATS *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)        
        return sbp->ipv4_table->mc.memcap;

    return -1;            
}

/** 
 * get the node count
 * 
 * @param sbp server_stats ptr to return the memcap of
 * 
 * @return nrows or -1
 */
int server_stats_row_count(SERVER_STATS *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)        
        return sbp->ipv4_table->nrows;

    return -1;            
}


/** 
 * get the overhead # of bytes
 * 
 * @param sbp server_stats ptr to return the memcap of
 * 
 * @return nrows or -1
 */
int server_stats_overhead_bytes(SERVER_STATS *sbp)
{
    if(sbp != NULL && sbp->ipv4_table != NULL)
        return sfxhash_overhead_bytes(sbp->ipv4_table);

    return -1;            
}


