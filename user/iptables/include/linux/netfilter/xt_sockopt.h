/* Header file for kernel module to match sockopt information.
 */

#ifndef _XT_SOCKOPT_H
#define _XT_SOCKOPT_H

#include <linux/types.h>

/* flags, invflags: */
enum {
	XT_SOCKOPT_ORIGDEV        = 1 << 0,
	XT_SOCKOPT_ORIGSRC        = 1 << 1,
	XT_SOCKOPT_ORIGDST        = 1 << 2,
	XT_SOCKOPT_SRCRANGE       = 1 << 3,
	XT_SOCKOPT_DSTRANGE       = 1 << 4,
};

struct xt_sockopt_mtinfo {
	u_int32_t origdev;
	union nf_inet_addr origsrc_addr, origsrc_mask;
	union nf_inet_addr origdst_addr, origdst_mask;
	u_int8_t match, invert;
};

#endif /*_XT_SOCKOPT_H*/
