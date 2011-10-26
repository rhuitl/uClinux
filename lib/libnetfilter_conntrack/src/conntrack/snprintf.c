/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#include "internal.h"

int __snprintf_conntrack(char *buf,
			 unsigned int len,
			 const struct nf_conntrack *ct,
			 unsigned int type,
			 unsigned int msg_output,
			 unsigned int flags)
{
	int size;

	switch(msg_output) {
	case NFCT_O_DEFAULT:
		size = __snprintf_conntrack_default(buf, len, ct, type, flags);
		break;
	case NFCT_O_XML:
		size = __snprintf_conntrack_xml(buf, len, ct, type, flags);
		break;
	default:
		errno = ENOENT;
		return -1;
	}

	/* NULL terminated string */
	buf[size+1 > len ? len-1 : size] = '\0';

	return size;
}
