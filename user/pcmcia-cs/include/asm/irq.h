#ifndef PCMCIA_IRQ_H
#define PCMCIA_IRQ_H

#include <linux/version.h>
#include_next <asm/irq.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0))
#define disable_irq_nosync(x)	disable_irq(x)
#endif

#endif
