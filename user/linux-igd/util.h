#ifndef _UTIL_H_
#define _UTIL_H_

int get_sockfd(void);
int GetIpAddressStr(char *address, char *ifname);
void trace(int debuglevel, const char *format, ...);

#endif //_UTIL_H_
