/*
 * (C) 2006-2007 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

static int __snprintf_expect_proto(char *buf, 
				   unsigned int len,
				   const struct nf_expect *exp)
{
	 return(snprintf(buf, len, "%u proto=%d ", 
	 		 exp->timeout, 
			 exp->expected.tuple[__DIR_ORIG].protonum));
}

int __snprintf_expect_default(char *buf, 
			      unsigned int len,
			      const struct nf_expect *exp,
			      unsigned int msg_type,
			      unsigned int flags) 
{
	int ret = 0, size = 0, offset = 0;

	switch(msg_type) {
		case NFCT_T_NEW:
			ret = snprintf(buf, len, "%9s ", "[NEW]");
			break;
		default:
			break;
	}

	BUFFER_SIZE(ret, size, len, offset);

	ret = __snprintf_expect_proto(buf+offset, len, exp);
	BUFFER_SIZE(ret, size, len, offset);

	ret = __snprintf_address(buf+offset, len, &exp->expected.tuple[__DIR_ORIG]);
	BUFFER_SIZE(ret, size, len, offset);

	ret = __snprintf_proto(buf+offset, len, &exp->expected.tuple[__DIR_ORIG]);
	BUFFER_SIZE(ret, size, len, offset);

	/* Delete the last blank space */
	size--;

	return size;
}
