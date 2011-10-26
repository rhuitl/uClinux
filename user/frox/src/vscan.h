#ifndef VSCAN_H
#define VSCAN_H

#include "config.h"
#include "sstr.h"

/*****************
**    vscan.c   **
******************/
#ifdef DO_VSCAN
int vscan_init(void);
void vscan_new(int sz);
void vscan_inc(sstr * inc);
int vscan_switchover(void);
int vscan_end(void);
void vscan_abort(void);
int vscan_parsed_reply(int code, sstr * msg);
#else
static inline void vscan_init(void)
{
};
static inline void vscan_new(int sz)
{
};
static inline void vscan_inc(sstr * inc)
{
};
static inline int vscan_switchover(void)
{
	return 0;
};
static inline int vscan_end(void)
{
	return -1;
};
static inline void vscan_abort(void)
{
};
static inline int vscan_parsed_reply(int code, sstr * msg)
{
	return 0;
};
#endif

#define VSCAN_OK -1
#define VSCAN_FAIL -2

#endif /*VSCAN_H */
