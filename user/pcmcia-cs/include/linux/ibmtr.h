#ifndef _COMPAT_IBMTR_H
#define _COMPAT_IBMTR_H

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,4,0))
#include_next <linux/ibmtr.h>
#else
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,3,21))
#include <../drivers/net/tokenring/ibmtr.h>
#else
#include <../drivers/net/ibmtr.h>
#endif
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,100))
extern struct timer_list tr_timer;
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,1,16))
#define register_trdev register_netdev
#define unregister_trdev unregister_netdev
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0))
static inline struct net_device *init_trdev(void *p, int n)
{
    struct net_device *dev;
    dev = kmalloc(sizeof(struct net_device), GFP_KERNEL);
    if (dev)
	memset(dev, 0, sizeof(struct net_device));
    return dev;
}
#endif

#endif /* _COMPAT_IBMTR_H */
