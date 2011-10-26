/**
 * @file   util_net.h
 * @author Chris Green <cmg@sourcefire.com>
 * @date   Fri Jun 27 10:20:31 2003
 * 
 * @brief  simple network related functions
 * 
 * Put your simple network related functions here
 */

#ifndef _UTIL_NET_H
#define _UTIL_NET_H

char *inet_ntoax(u_int32_t ip);
char * mktcpflag_str(int flags);

#endif /* _UTIL_NET_H */
