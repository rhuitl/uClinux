#ifndef _PCMCIA_BYTEORDER_H
#define _PCMCIA_BYTEORDER_H

#include <linux/version.h>
#include_next <asm/byteorder.h>

#ifndef le16_to_cpu
#define le16_to_cpu(x)		(x)
#define le16_to_cpup(x)		(*(x))
#define le32_to_cpu(x)		(x)
#define le32_to_cpup(x)		(*(x))
#define cpu_to_le16(x)		(x)
#define cpu_to_le32(x)		(x)
#define be16_to_cpu(x)		ntohs(x)
#define be16_to_cpup(x)		ntohs(*(x))
#define be32_to_cpu(x)		ntohl(x)
#define be32_to_cpup(x)		ntohl(*(x))
#define cpu_to_be16(x)		htons(x)
#define cpu_to_be32(x)		htonl(x)
#define cpu_to_le16s(x)		do { } while (0)
#define cpu_to_le32s(x)		do { } while (0)
#endif

#endif /* _PCMCIA_BYTEORDER_H */
