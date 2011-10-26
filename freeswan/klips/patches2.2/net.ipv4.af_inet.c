RCSID $Id: net.ipv4.af_inet.c,v 1.5 1999/12/31 15:15:21 rgb Exp $
--- ./net/ipv4/af_inet.c.preipsec	Mon Aug  9 15:05:13 1999
+++ ./net/ipv4/af_inet.c	Fri Sep 17 10:13:07 1999
@@ -1140,6 +1140,17 @@
 	ip_mr_init();
 #endif
 
+#if defined(CONFIG_IPSEC)
+	{
+               extern /* void */ int ipsec_init(void);
+		/*
+		 *  Initialise AF_INET ESP and AH protocol support including 
+		 *  e-routing and SA tables
+		 */
+		ipsec_init();
+	}
+#endif /* CONFIG_IPSEC */
+
 #ifdef CONFIG_INET_RARP
 	rarp_ioctl_hook = rarp_ioctl;
 #endif
