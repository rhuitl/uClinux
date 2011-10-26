#
# Makefile
#
# This is the Makefile for the whole vgetty stuff.
#
# $Id: Makefile,v 1.7 2001/12/23 14:23:55 marcs Exp $
#

AR=ar
ARFLAGS=rc
RANLIB=ranlib
CC=gcc
LN=ln
MV=mv
RM=rm

MGETTYLIB=../../getdisk.o ../../goodies.o ../../io.o \
	../../locks.o ../../tio.o ../../modem.o \
	../../class1.o ../../class1lib.o

LIBDIRS=libpvf libutil libvoice libmgsm
LIBPVF=../libpvf/libpvf.a
LIBUTIL=../libutil/libutil.a
LIBVOICE=../libvoice/libvoice.a
LIBGSM=../libmgsm/libmgsm.a

PROGRAMDIRS=pvftools vgetty vm

PVFTOOLS=pvfamp pvfcut pvfecho pvffile pvffilter pvffft pvfmix pvfnoise \
	pvfreverse pvfsine pvfspeed pvftormd rmdtopvf rmdfile pvftovoc \
	voctopvf pvftolin lintopvf pvftobasic basictopvf pvftoau autopvf \
	pvftowav wavtopvf
                        
SUBDIRS=$(LIBDIRS) $(PROGRAMDIRS)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

all: ../policy.h
	cd ..; $(MAKE) vgetty

install:
	cd ..; $(MAKE) vgetty-install

shell_scripts: ../sedscript
	for i in $(SHELLSCRIPTS); do ../sedscript <$$i.in >$$i; chmod 750 $$i;\
	 done

../policy.h:
	@echo ""
	@echo "You didn't build mgetty first. Please read the documentation."
	@echo ""
	@exit 1

../sedscript: ../policy.h ../Makefile ../mksed.c
	@cd .. ; $(MAKE) sedscript

all-message:
	@echo ""
	@echo "  Building the voice extensions"
	@echo "  -----------------------------"
	@echo ""

vgetty-all: all-message # shell_scripts
	@for i in $(SUBDIRS) ;\
	do \
		echo "In "$$i"..." ;\
		cd $$i ;\
		$(MAKE) AR="$(AR)" ARFLAGS="$(ARFLAGS)" CC="$(CC)" \
		 CFLAGS="$(CFLAGS)" CONFDIR="$(CONFDIR)" \
		 VARRUNDIR="$(VARRUNDIR)" \
		 FAX_SPOOL_IN="$(FAX_SPOOL_IN)" LIBPVF="$(LIBPVF)" \
		 LIBUTIL="$(LIBUTIL)" LIBVOICE="$(LIBVOICE)" \
		 LIBGSM="$(LIBGSM)" LIBS="$(LIBS)" \
		 LDFLAGS="$(LDFLAGS)" LN="$(LN)" MGETTYLIB="$(MGETTYLIB)" \
		 MV="$(MV)" PVFTOOLS="$(PVFTOOLS)" RANLIB="$(RANLIB)" \
		 RM="$(RM)" SHELL="$(SHELL)" || exit 1 ;\
		cd .. ;\
	done

vgetty-install: vgetty-all
	@echo ""
	@echo "  Installing the voice extensions"
	@echo "  -------------------------------"
	@echo ""
	$(INSTALL) -m 700 vgetty/vgetty $(SBINDIR)
	$(INSTALL) -m 755 vm/vm $(BINDIR)
	for i in $(PVFTOOLS); \
	do \
	     $(INSTALL) -m 755 pvftools/$$i $(BINDIR); \
	done
	$(INSTALL) -m 644 man/man1/zplay.1 $(MAN1DIR)
	$(INSTALL) -m 644 man/man1/pvf.1 $(MAN1DIR)
	$(INSTALL) -m 644 man/man8/vgetty.8 $(MAN8DIR)
	cd $(MAN1DIR); \
	for i in $(PVFTOOLS); \
	do \
	     $(RM) -f $$i.1; $(LN) -s pvf.1 $$i.1; \
	done
#	[ -d $(VOICE_DIR) ] || mkdir $(VOICE_DIR)
#	[ -d $(VOICE_DIR)/incoming ] || mkdir $(VOICE_DIR)/incoming
#	chown 0 $(VOICE_DIR)/incoming
#	chgrp $(PHONE_GROUP) $(VOICE_DIR)/incoming
#	chmod $(PHONE_PERMS) $(VOICE_DIR)/incoming
#	[ -d $(VOICE_DIR)/messages ] || mkdir $(VOICE_DIR)/messages
#	for i in $(SHELLSCRIPTS); do \
#		$(INSTALL) -m 755 $$i $(VOICE_DIR) ;\
#	done
#	[ -f $(VOICE_DIR)/.code ] || echo '12345' >$(VOICE_DIR)/.code
#	chgrp $(PHONE_GROUP) $(VOICE_DIR)/.code
#	chmod $(PHONE_PERMS) $(VOICE_DIR)/.code
#	chmod 660 $(VOICE_DIR)/.code
#	[ -f $(VOICE_DIR)/messages/Index ] || \
#	 echo 'put_filename_here' >$(VOICE_DIR)/messages/Index

clean:
	@echo "Cleaning..."
	@$(RM) -f $(MAIN) $(PVFTOOLS) $(SHELLSCRIPTS) ../vgetty.c
	@for i in $(SUBDIRS) ;\
	do \
		echo "In "$$i"..." ;\
		cd $$i ;\
		$(MAKE) RM="$(RM)" PVFTOOLS="$(PVFTOOLS)" clean || exit 1 ;\
		cd .. ;\
	done

fullclean: clean
