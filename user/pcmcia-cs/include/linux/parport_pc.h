#ifndef _COMPAT_PARPORT_PC_H
#define _COMPAT_PARPORT_PC_H

#include_next <linux/parport_pc.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,6))
#define PARPORT_MODE_TRISTATE	PARPORT_MODE_PCPS2
#define PARPORT_MODE_EPP	PARPORT_MODE_PCEPP
#define PARPORT_MODE_ECP	PARPORT_MODE_PCECP
#define parport_pc_probe_port(io1, io2, irq, dma, ops) \
	parport_register_port(io1, irq, dma, &parport_cs_ops)
#endif

#endif /* _COMPAT_PARPORT_PC_H */
