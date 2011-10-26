RCSID $Id: drivers.isdn.isdn_net.c,v 1.3 1999/09/17 17:54:44 rgb Exp $
--- ./drivers/isdn/isdn_net.c.preipsec	Mon Aug  9 15:04:39 1999
+++ ./drivers/isdn/isdn_net.c	Sat Aug 28 02:24:58 1999
@@ -1154,6 +1154,12 @@
 				case 22:
 					strcpy(addinfo, " IDP");
 					break;
+				case IPPROTO_ESP:
+					strcpy(addinfo, " ESP");
+					break;
+				case IPPROTO_AH:
+					strcpy(addinfo, " AH");
+					break;
 			}
 			printk(KERN_INFO "OPEN: %d.%d.%d.%d -> %d.%d.%d.%d%s\n",
 			       p[12], p[13], p[14], p[15],
