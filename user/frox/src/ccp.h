#ifndef CCP_H
#define CCP_H

#include <sys/types.h>
#include "config.h"
#include "sstr.h"

/*****************
**     ccp.c    **
******************/
#ifdef USE_CCP
void ccp_changedest(void);
int ccp_allowcmd(sstr * cmd, sstr * arg);
int ccp_allowmsg(int *code, sstr * msg);
#else
static inline void ccp_changedest(void)
{
};
static inline int ccp_allowcmd(sstr * cmd, sstr * arg)
{
	return TRUE;
};
static inline int ccp_allowmsg(int *code, sstr * msg)
{
	return TRUE;
};
#endif






#endif /*CCP_H */
