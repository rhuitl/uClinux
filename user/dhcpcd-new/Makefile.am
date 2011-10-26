EXTRA_DIST		=		\
	README				\
	@PACKAGE@-@DHCPCD_VERSION@.lsm	\
	@PACKAGE@.spec.in		\
	$(man_MANS)			\
	dhcpcd-eth0.exe			\
	pcmcia/2.8.23/README		\
	pcmcia/2.8.23/README.jis	\
	pcmcia/2.8.23/network		\
	pcmcia/2.8.23/network.opts	\
	pcmcia/2.9.7/network		\
	pcmcia/2.9.7/network.opts	\
	rc.d/README			\
	rc.d/rc.M			\
	rc.d/rc.dhcp			\
	rc.d/rc.inet1			\
	rc.d/rc.inet2

man_MANS		= @PACKAGE@.8

sbin_PROGRAMS		= dhcpcd 

dhcpcd_SOURCES		=	\
	peekfd.c		\
	udpipgen.c		\
	buildmsg.c		\
	signals.c		\
	arp.c			\
	client.c		\
	dhcpcd.c		\
	signals.h		\
	buildmsg.h		\
	client.h		\
	dhcpcd.h		\
	pathnames.h		\
	signals.h		\
	udpipgen.h

configdir		= ${sysconfdir}/dhcpc

config_DATA		=	

noinst_DATA		= dhcpcd.spec

## Ideally those files should not be in the distribution, but the
## world is not perfect. RedHat needs dhcpcd.spec with a fixed version
## number. And i386-Linux users want a binary here and now.
dist-hook:
	cp dhcpcd.spec $(distdir)
	cp dhcpcd $(distdir)

#
# Rule to build RPM distribution package
#
rpm: distcheck
	rpm -ta $(distdir).tar.gz
