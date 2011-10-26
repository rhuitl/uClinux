RCSID $Id: net.Makefile,v 1.5 2001/11/07 02:17:56 rgb Exp $
--- net/Makefile.preipsec	Mon Jun 11 22:15:27 2001
+++ net/Makefile	Tue Nov  6 21:07:43 2001
@@ -17,6 +17,7 @@
 subdir-$(CONFIG_NET)		+= 802 sched
 subdir-$(CONFIG_INET)		+= ipv4
 subdir-$(CONFIG_NETFILTER)	+= ipv4/netfilter
+subdir-$(CONFIG_IPSEC)		+= ipsec
 subdir-$(CONFIG_UNIX)		+= unix
 subdir-$(CONFIG_IPV6)		+= ipv6
 
