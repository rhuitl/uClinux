RCSID $Id: include.linux.socket.h,v 1.1 1999/05/05 22:02:37 rgb Exp $
--- ./include/linux/socket.h.preipsec	Thu Apr 29 23:19:06 1999
+++ ./include/linux/socket.h	Thu Apr 29 23:23:58 1999
@@ -158,7 +158,7 @@
 #define AF_DECnet	12	/* Reserved for DECnet project	*/
 #define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
 #define AF_SECURITY	14	/* Security callback pseudo AF */
-#define pseudo_AF_KEY   15      /* PF_KEY key management API */
+#define AF_KEY		15      /* PF_KEY key management API    */
 #define AF_NETLINK	16
 #define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD */
 #define AF_PACKET	17	/* Packet family		*/
@@ -186,7 +186,7 @@
 #define PF_DECnet	AF_DECnet
 #define PF_NETBEUI	AF_NETBEUI
 #define PF_SECURITY	AF_SECURITY
-#define PF_KEY          pseudo_AF_KEY
+#define PF_KEY          AF_KEY
 #define PF_NETLINK	AF_NETLINK
 #define PF_ROUTE	AF_ROUTE
 #define PF_PACKET	AF_PACKET
