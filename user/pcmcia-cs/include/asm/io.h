#ifndef _PCMCIA_IO_H
#define _PCMCIA_IO_H

#include <linux/version.h>
#include_next <asm/io.h>

#ifndef readw_ns
#ifdef __powerpc__

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0))
#define readw_ns(p)		ld_be16((volatile unsigned short *)(p))
#define readl_ns(p)		ld_be32((volatile unsigned *)(p))
#define writew_ns(v,p)		st_be16((volatile unsigned short *)(p),(v))
#define writel_ns(v,p)		st_be32((volatile unsigned *)(p),(v))
#else
#define readw_ns(p)		in_be16((volatile unsigned short *)(p))
#define readl_ns(p)		in_be32((volatile unsigned *)(p))
#define writew_ns(v,p)		out_be16((volatile unsigned short *)(p),(v))
#define writel_ns(v,p)		out_be32((volatile unsigned *)(p),(v))
#endif
#define inw_ns(p)		in_be16((unsigned short *)((p)+_IO_BASE))
#define inl_ns(p)		in_be32((unsigned *)((p)+_IO_BASE))
#define outw_ns(v,p)		out_be16((unsigned short *)((p)+_IO_BASE),(v))
#define outl_ns(v,p)		out_be32((unsigned *)((p)+_IO_BASE),(v))

#else /* __powerpc__ */

#define readw_ns(p)		readw(p)
#define readl_ns(p)		readl(p)
#define writew_ns(v,p)		writew(v,p)
#define writel_ns(v,p)		writel(v,p)
#define inw_ns(p)		inw(p)
#define inl_ns(p)		inl(p)
#define outw_ns(v,p)		outw(v,p)
#define outl_ns(v,p)		outl(v,p)

#endif /* __powerpc__ */
#endif /* readw_ns */

#ifndef insw_ns
#define insw_ns(p,b,l)		insw(p,b,l)
#define insl_ns(p,b,l)		insl(p,b,l)
#define outsw_ns(p,b,l)		outsw(p,b,l)
#define outsl_ns(p,b,l)		outsl(p,b,l)
#endif

#endif /* _PCMCIA_IO_H */
