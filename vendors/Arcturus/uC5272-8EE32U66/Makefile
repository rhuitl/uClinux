#
#	Makefile -- Build instructions for Arcturus/uC5272
#

COMMON="$(ROOTDIR)/vendors/Arcturus/uC5272/"

DIRS = 

ROMFSIMG = $(IMAGEDIR)/romfs.img
IMAGE    = $(IMAGEDIR)/image.bin

ROMFS_DIRS = bin dev etc etc/rc.d home lib mnt proc \
             usr var home/httpd home/httpd/cgi-bin

DEVICES = \
	tty,c,5,0      console,c,5,1      cua0,c,5,64      cua1,c,5,65  \
	mem,c,1,1      kmem,c,1,2         null,c,1,3       \
	\
	zero,c,1,5     random,c,1,8       urandom,c,1,9    watchdog,c,10,130 \
	\
	ptyp0,c,2,0    ptyp1,c,2,1        ptyp2,c,2,2      ptyp3,c,2,3 \
	ptyp4,c,2,4    ptyp5,c,2,5        ptyp6,c,2,6      ptyp7,c,2,7 \
	ptyp8,c,2,8    ptyp9,c,2,9        ptypa,c,2,10     ptypb,c,2,11 \
	ptypc,c,2,12   ptypd,c,2,13       ptype,c,2,14     ptypf,c,2,15 \
	\
	ram0,b,1,0     ram1,b,1,1         ram2,b,1,2       ram3,b,1,3 \
	\
	mtdblock0,b,31,0    mtdblock1,b,31,1        mtdblock2,b,31,2      mtdblock3,b,31,3 \
	mtdblock4,b,31,4    mtdblock5,b,31,5        mtdblock6,b,31,6      mtdblock7,b,31,7 \
	rom0,b,31,0    rom1,b,31,1        rom2,b,31,2      rom3,b,31,3 \
	rom4,b,31,4    rom5,b,31,5        rom6,b,31,6      rom7,b,31,7 \
	rom8,b,31,8    rom9,b,31,9 \
	\
	tty0,c,4,0     tty1,c,4,1         tty2,c,4,2       tty3,c,4,3 \
	ttyS0,c,4,64   ttyS1,c,4,65 \
	\
	ttyp0,c,3,0    ttyp1,c,3,1        ttyp2,c,3,2      ttyp3,c,3,3 \
	ttyp4,c,3,4    ttyp5,c,3,5        ttyp6,c,3,6      ttyp7,c,3,7 \
	ttyp8,c,3,8    ttyp9,c,3,9        ttypa,c,3,10     ttypb,c,3,11 \
	ttypc,c,3,12   ttypd,c,3,13       ttype,c,3,14     ttypf,c,3,15 \
	\
	loop0,b,7,0    loop1,b,7,1        loop2,b,7,2      loop3,b,7,3 \
	loop4,b,7,4    loop5,b,7,5        loop6,b,7,6      loop7,b,7,7 \
	\
	qspi0,c,126,0    qspi1,c,126,1     qspi2,c,126,2     qspi3,c,126,3 \
	qspi4,c,126,4    qspi5,c,126,5     qspi6,c,126,6     qspi7,c,126,7 \
	qspi8,c,126,8    qspi9,c,126,9     qspi10,c,126,10   qspi11,c,126,11 \
	qspi12,c,126,12  qspi13,c,126,13   qspi14,c,126,14 \
	\
	ipsec,c,36,10 \
	ppp,c,108,0 pppox0,c,144,0 \
	hifn0,c,28,0


all:
	dirs=$(DIRS) ; \
	for i in $$dirs ; do  make -C $$i || exit $? ; done

clean:
	-dirs=$(DIRS) ; \
	for i in $$dirs; do [ ! -d $$i ] || make -C $$i clean; done
	make -C $(ROOTDIR)/user/boottools/uCbootstrap-tools clean
	make -C $(ROOTDIR)/user/cramfs/host_build clean

devices: device_dir
	for i in $(DEVICES); do  touch $(ROMFSDIR)/dev/@$$i;  done


device_dir:
	[ -d $(ROMFSDIR)/dev ] || mkdir -p $(ROMFSDIR)/dev 


romfs:	devices
	[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)
	for i in $(ROMFS_DIRS); do \
		[ -d $(ROMFSDIR)/$$i ] || mkdir -p $(ROMFSDIR)/$$i; \
	done
	dirs=$(DIRS) ; for i in $$dirs; do make -C $$i romfs || exit $? ; done
	$(ROMFSINST) -s /var/tmp /tmp
	$(ROMFSINST) -s /var/profile /etc/profile
	$(ROMFSINST) -s /var/resolv.conf /etc/resolv.conf
	$(ROMFSINST) -s /var/dhcpc /etc/dhcpc
	$(ROMFSINST) -p 555 $(COMMON)rc /etc/rc
	$(ROMFSINST) -p 555 $(COMMON)rc.d/rc.net /etc/rc.d/rc.net
	$(ROMFSINST) -p 555 $(COMMON)rc.d/rc.dhcpc /etc/rc.d/rc.dhcpc
	$(ROMFSINST) -p 555 $(COMMON)rc.d/rc.qspi /etc/rc.d/rc.qspi
	$(ROMFSINST) $(COMMON)inittab /etc/inittab
	$(ROMFSINST) $(COMMON)services /etc/services
	$(ROMFSINST) $(COMMON)issue /etc/issue
	$(ROMFSINST) $(COMMON)passwd /etc/passwd
	if [ $(CONFIG_BLK_DEV_INITRD) = "y" ]; then \
		ln -sf bin/init $(ROMFSDIR)/linuxrc; \
	fi
	$(ROMFSINST) $(COMMON)htdocs/index.html /home/httpd/index.html
	$(ROMFSINST) $(COMMON)htdocs/info.html /home/httpd/info.html
	$(ROMFSINST) $(COMMON)htdocs/arcturuslogo.gif /home/httpd/arcturuslogo.gif
	$(ROMFSINST) $(COMMON)htdocs/miniuclinux2.gif /home/httpd/miniuclinux2.gif
	$(ROMFSINST) $(COMMON)htdocs/5272pic.gif /home/httpd/5272pic.gif
	$(ROMFSINST) -p 555 $(COMMON)htdocs/cgi-bin/benv.cgi /home/httpd/cgi-bin/benv.cgi
	$(ROMFSINST) -p 555 $(COMMON)htdocs/cgi-bin/cpuinfo.cgi /home/httpd/cgi-bin/cpuinfo.cgi
	$(ROMFSINST) -p 555 $(COMMON)htdocs/cgi-bin/ifconfig.cgi /home/httpd/cgi-bin/ifconfig.cgi
	$(ROMFSINST) -p 555 $(COMMON)htdocs/cgi-bin/interrupts.cgi /home/httpd/cgi-bin/interrupts.cgi
	$(ROMFSINST) -p 555 $(COMMON)htdocs/cgi-bin/mem_map.cgi /home/httpd/cgi-bin/mem_map.cgi
	$(ROMFSINST) -p 555 $(COMMON)htdocs/cgi-bin/ps.cgi /home/httpd/cgi-bin/ps.cgi
	$(ROMFSINST) -p 555 $(COMMON)htdocs/cgi-bin/kmsg.cgi /home/httpd/cgi-bin/kmsg.cgi
	echo "$(VERSIONSTR) -- " `date` > $(ROMFSDIR)/etc/version

image-tools:
	touch $(ROOTDIR)/user/boottools/.sgbuilt_user && make -C $(ROOTDIR)/user/boottools uCbootstrap-tools 
	touch $(ROOTDIR)/user/cramfs/.sgbuilt_user && make -C $(ROOTDIR)/user/cramfs host_build

image: image-tools
	[ -d $(IMAGEDIR) ] || mkdir -p $(IMAGEDIR)
	rm -rf $(IMAGEDIR)/*
	$(CROSS)objcopy  --set-section-flags=.romvec=alloc,load,readonly,data \
			-O binary $(ROOTDIR)/$(LINUXDIR)/linux \
			$(ROMFSDIR)/linux.bin
	(cd ${ROMFSDIR}/bin; if [ -f ls ] ; then $(CROSS)flthdr -r -s 8192 ls; fi )
	(cd ${ROMFSDIR}/bin; if [ -f thttpd ] ; then $(CROSS)flthdr -r -s 20480 thttpd; fi )
	(cd ${ROMFSDIR}/bin; if [ -f busybox ] ; then $(CROSS)flthdr -r -s 12288 busybox; fi )
ifdef FORCED_STACK_SIZE
	(cd $(ROMFSDIR)/bin; for i in `find -type f` ; do J=`$(CROSS)flthdr -p $$i | grep "Stack" | sed -e "s/Stack Size://g" | sed -e "s/ //g" | sed -e "s/0x//"` ; if [ "$$J" == "1000" ] ; then $(CROSS)flthdr -r -s $$FORCED_STACK_SIZE $$i ; echo "Increased the stack of $$i to $$FORCED_STACK_SIZE" ; fi   ; done)
endif
	$(ROOTDIR)/user/cramfs/host_build/mkcramfs -r -n uClinux \
		$(ROMFSDIR) $(IMAGEDIR)/image.cramfs 
	$(ROOTDIR)/user/boottools/uCbootstrap-tools/uCmkimage \
		-f $(IMAGEDIR)/image.cramfs -o $(IMAGEDIR)/image.ucb \
		-t `date -I` -n "uC5272 cramfs image"
	$(ROOTDIR)/user/boottools/uCbootstrap-tools/uCheader $(IMAGEDIR)/image.ucb

.PHONY:	image-tools
