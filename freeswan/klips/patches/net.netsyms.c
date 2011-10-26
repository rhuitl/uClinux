RCSID $Id: net.netsyms.c,v 1.10 1999/04/29 15:25:47 rgb Exp $
--- ./net/netsyms.c.preipsec	Mon Apr  5 05:17:47 1999
+++ ./net/netsyms.c	Thu Apr 22 18:54:00 1999
@@ -110,6 +110,9 @@
 	X(ip_id_count),
 	X(ip_send_check),
 	X(ip_forward),
+	X(ip_queue_xmit),
+	X(ip_fragment),
+	X(ip_chk_addr),
 	X(sysctl_ip_forward),
 
 #if	defined(CONFIG_ULTRA)	||	defined(CONFIG_WD80x3)		|| \
