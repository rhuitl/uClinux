RCSID $Id: net.Makefile,v 1.6 1999/11/17 14:38:16 rgb Exp $
--- ./net/Makefile.preipsec	Mon Jul 13 16:47:40 1998
+++ ./net/Makefile	Thu Sep 16 11:26:31 1999
@@ -64,6 +64,16 @@
   endif
 endif
 
+ifeq ($(CONFIG_IPSEC),y)
+ALL_SUB_DIRS += ipsec
+SUB_DIRS += ipsec
+else
+  ifeq ($(CONFIG_IPSEC),m)
+  ALL_SUB_DIRS += ipsec
+  MOD_SUB_DIRS += ipsec
+  endif
+endif
+
 L_TARGET     := network.a
 L_OBJS	     := socket.o protocols.o sysctl_net.o $(join $(SUB_DIRS),$(SUB_DIRS:%=/%.o))
 ifeq ($(CONFIG_NET),y)
