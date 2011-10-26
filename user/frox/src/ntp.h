#ifndef NTP_H
#define NTP_H

#include "config.h"

/*****************
**     ntp.c    **
******************/
#ifdef NON_TRANS_PROXY
void ntp_changedest(void);
void ntp_senduser(void);
#else
static inline void ntp_changedest(void)
{
};
static inline void ntp_senduser(void)
{
};
#endif

#endif /*NTP_H */
