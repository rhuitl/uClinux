RCSID $Id: include.linux.socket.h,v 1.5 1999/09/17 17:48:36 rgb Exp $
--- ./include/linux/socket.h.preipsec	Mon Jul 13 16:47:39 1998
+++ ./include/linux/socket.h	Thu Sep 16 11:26:32 1999
@@ -64,8 +64,9 @@
 #define AF_INET6	10	/* IP version 6			*/
 #endif
 #define AF_ROSE		11	/* Amateur Radio X.25 PLP       */
-#define AF_MAX		13	/* For now.. */
+#define AF_KEY		15	/* PF_KEY security key inferface	*/
 #define AF_PACKET	17	/* Forward compat hook		*/
+#define AF_MAX		32	/* For now.. */
 
 /* Protocol families, same as address families. */
 #define PF_UNSPEC	AF_UNSPEC
@@ -82,6 +83,7 @@
 #define PF_INET6	AF_INET6
 #endif
 #define	PF_ROSE		AF_ROSE
+#define PF_KEY		AF_KEY
 #define PF_MAX		AF_MAX
 #define PF_PACKET	AF_PACKET
 /* Maximum queue length specifiable by listen.  */
