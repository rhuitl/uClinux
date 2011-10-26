RCSID $Id: drivers.isdn.isdn_net.c,v 1.4 1999/09/17 17:48:35 rgb Exp $
--- ./drivers/isdn/isdn_net.c.preipsec	Sun Jun 13 13:21:01 1999
+++ ./drivers/isdn/isdn_net.c	Thu Sep 16 11:26:31 1999
@@ -1133,6 +1133,12 @@
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
