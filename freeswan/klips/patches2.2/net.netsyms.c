RCSID $Id: net.netsyms.c,v 1.1 1999/07/09 16:29:24 rgb Exp $
--- ./net/netsyms.c.preipsec	Sat Apr 24 20:51:48 1999
+++ ./net/netsyms.c	Fri Jul  9 11:16:36 1999
@@ -183,6 +183,9 @@
 EXPORT_SYMBOL(neigh_parms_alloc);
 EXPORT_SYMBOL(neigh_parms_release);
 EXPORT_SYMBOL(neigh_rand_reach_time);
+#ifdef CONFIG_IPSEC_MODULE
+EXPORT_SYMBOL(neigh_compat_output);
+#endif /* CONFIG_IPSEC_MODULE */
 
 /*	dst_entry	*/
 EXPORT_SYMBOL(dst_alloc);
@@ -351,6 +354,10 @@
 #ifdef CONFIG_SYSCTL
 EXPORT_SYMBOL(sysctl_max_syn_backlog);
 #endif
+#else
+#ifdef CONFIG_IPSEC_MODULE
+EXPORT_SYMBOL(inet_addr_type);
+#endif /* CONFIG_IPSEC_MODULE */
 #endif
 
 #ifdef CONFIG_NETLINK
