#ifndef HOSTAP_WEXT_H
#define HOSTAP_WEXT_H

/* Linux Wireless Extensions compatibility code */

#include <linux/wireless.h>
#include <net/iw_handler.h>

/* if wireless ext is not supported */
#ifndef IW_MODE_ADHOC
#define IW_MODE_ADHOC 1
#endif
#ifndef IW_MODE_INFRA
#define IW_MODE_INFRA 2
#endif
#ifndef IW_MODE_MASTER
#define IW_MODE_MASTER 3
#endif
#ifndef IW_MODE_REPEAT
#define IW_MODE_REPEAT 4
#endif
#ifndef IW_MODE_SECOND
#define IW_MODE_SECOND 5
#endif
#ifndef IW_MODE_MONITOR
#define IW_MODE_MONITOR 6
#endif


/* Conversion to new driver API by Jean II */

#if WIRELESS_EXT >= 15
/* Wireless ext ver15 allows verification of iwpriv support and sub-ioctls can
 * be included even if not especially configured. */
#ifndef PRISM2_USE_WE_SUB_IOCTLS
#define PRISM2_USE_WE_SUB_IOCTLS
#endif /* PRISM2_USE_WE_SUB_IOCTLS */

/* Assume that hosts using new wireless ext also have new wireless tools
 * (ver >= 25) */
#ifndef PRISM2_USE_WE_TYPE_ADDR
#define PRISM2_USE_WE_TYPE_ADDR
#endif /* PRISM2_USE_WE_TYPE_ADDR */
#endif /* WIRELESS_EXT >= 15 */


#ifdef PRISM2_USE_WE_TYPE_ADDR
/* Added in WIRELESS_EXT 15, but can be used with older versions assuming
 * iwpriv ver >= 25 */
#ifndef IW_PRIV_TYPE_ADDR
#define IW_PRIV_TYPE_ADDR 0x6000
#endif /* IW_PRIV_TYPE_ADDR */
#endif /* PRISM2_USE_WE_TYPE_ADDR */

#endif /* HOSTAP_WEXT_H */
