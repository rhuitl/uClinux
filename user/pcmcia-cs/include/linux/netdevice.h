#ifndef _COMPAT_NETDEVICE_H
#define _COMPAT_NETDEVICE_H

#include <linux/version.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,25))
#define net_device_stats	enet_statistics
#define skb_tx_check(dev, skb) \
    do { if (skb == NULL) { dev_tint(dev); return 0; } \
    if (skb->len <= 0) return 0; } while (0)
#define add_rx_bytes(stats, n)	do { int x; x = (n); } while (0)
#define add_tx_bytes(stats, n)	do { int x; x = (n); } while (0)
#else
#define skb_tx_check(dev, skb)	do { } while (0)
#define add_rx_bytes(stats, n)	do { (stats)->rx_bytes += n; } while (0)
#define add_tx_bytes(stats, n)	do { (stats)->tx_bytes += n; } while (0)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,1,86))
#define DEV_KFREE_SKB(skb)      dev_kfree_skb(skb, FREE_WRITE)
#else
#define DEV_KFREE_SKB(skb)      dev_kfree_skb(skb)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,14))
#define net_device		device
#endif

#include_next <linux/netdevice.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,43))
#define netif_stop_queue(dev)	set_bit(0, (void *)&(dev)->tbusy)
#define netif_start_queue(dev)	clear_bit(0, (void *)&(dev)->tbusy)
#define netif_wake_queue(dev) \
    do { netif_start_queue(dev); mark_bh(NET_BH); } while (0)
#define netif_device_attach(dev) \
    do { (dev)->start = 1; netif_start_queue(dev); } while (0)
#define netif_device_detach(dev) \
    do { (dev)->start = 0; netif_stop_queue(dev); } while (0)
#define netif_device_present(dev) ((dev)->start)
#define netif_running(dev)	((dev)->start)
#define netif_mark_up(dev)	do { (dev)->start = 1; } while (0)
#define netif_mark_down(dev)	do { (dev)->start = 0; } while (0)
#define netif_carrier_on(dev)	do { dev->flags |= IFF_RUNNING; } while (0)
#define netif_carrier_off(dev)	do { dev->flags &= ~IFF_RUNNING; } while (0)
#define netif_queue_stopped(dev) ((dev)->tbusy)
#define tx_timeout_check(dev, tx_timeout) \
    do { if (test_and_set_bit(0, (void *)&(dev)->tbusy) != 0) { \
	if (jiffies - (dev)->trans_start < TX_TIMEOUT) return 1; \
	tx_timeout(dev); \
    } } while (0)
#define dev_kfree_skb_irq(skb)	DEV_KFREE_SKB(skb)
#else
#define netif_mark_up(dev)	do { } while (0)
#define netif_mark_down(dev)	do { } while (0)
#define tx_timeout_check(d,h)	netif_stop_queue(d)
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,3,99))
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,2,0))
/* A nasty hack: we only need to set up dev->init on 2.0.* kernels,
   and this is a convenient place to bury it */
#define init_dev_name(dev, node) \
  do { static int __dummy(struct net_device *dev) { return 0; } \
    dev->init = &__dummy; (dev)->name = (node).dev_name; \
  } while (0)
#else
#define init_dev_name(dev, node) (dev)->name = (node).dev_name
#endif
#define copy_dev_name(node, dev) do { } while (0)
#else
#define init_dev_name(dev, node) do { } while (0)
#define copy_dev_name(node, dev) strcpy((node).dev_name, (dev)->name)
#endif

#endif /* _COMPAT_NETDEVICE_H */
