RCSID $Id: net.Makefile,v 1.4 2000/06/30 20:00:14 rgb Exp $
--- ./net/Makefile.preipsec	Tue Jun 20 17:32:27 2000
+++ ./net/Makefile	Fri Jun 30 14:44:38 2000
@@ -195,6 +195,16 @@
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
 # We must attach netsyms.o to socket.o, as otherwise there is nothing
 # to pull the object file from the archive.
 
