/*
 * bitsizes.h
 *
 * Declaration for variable types with defined bit sizes
 *
 * $Id: bitsizes.h,v 1.4 1998/09/09 21:06:32 gert Exp $
 *
 */

typedef short              vgetty_s_int16;
typedef unsigned short     vgetty_u_int16;
typedef int                vgetty_s_int32;
typedef unsigned int       vgetty_u_int32;

#ifdef linux
 typedef int64_t            vgetty_s_int64;
 typedef u_int64_t          vgetty_u_int64;
#else
 typedef long long          vgetty_s_int64;
 typedef unsigned long long vgetty_u_int64;
#endif
