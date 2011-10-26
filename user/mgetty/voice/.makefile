#
# makefile for vgetty
#
# $Id: makefile,v 1.96 1998/09/09 19:16:41 marc Exp $
#
# This makefile contains local stuff
#

VERSION=0
SUBVERSION=9
STATE="e"  # experimental test release
#STATE="o" # official stable release

CP=cp
GCC=gcc
MV=mv
RM=rm
UUCP=/home/marc/bin/senduni

local-all: include/version.h depend all

include Makefile

version:
	@$(RM) -f include/version.h
	@DATE=`date +"%d%b%y"` ;\
	\
	if [ $(STATE) = "e" ] ; then \
		RELEASETYPE="experimental test release" ;\
	else \
		RELEASETYPE="official release" ;\
	fi ;\
	\
	PATCHLEVEL=`cat .patchlevel` ;\
	VERSIONSTRING=$(VERSION)"."$(SUBVERSION)"."$$PATCHLEVEL ;\
	RELEASESTRING=$$RELEASETYPE" "$$VERSIONSTRING" / "$$DATE ;\
	echo "Version is "$$RELEASESTRING"." ;\
	echo "char *vgetty_version = \""$$RELEASESTRING"\";" \
	 > include/version.h
	@chmod 444 include/version.h

include/version.h:
	@$(MAKE) version

depend: include/version.h
	@echo "Creating depend files..."
	@touch depend
	@for i in libpvf libutil libvoice libmgsm pvftools vgetty vm ;\
	do \
		echo $$i"/depend" ;\
		cd $$i ;\
		( \
			for i in `cat .files | grep ".c$$"` ;\
			do \
				\
				if [ "`basename $$i`" = "main.c" ]; then \
					$(GCC) -DMAIN -MM $$i ;\
				else \
					$(GCC)        -MM $$i ;\
				fi ;\
				\
			done ;\
		) > depend ;\
		\
		if [ "$$i" = "vgetty" ] ; then \
			$(GCC) -MM -DMAIN -DVOICE ../../mgetty.c | \
			 sed -e 's;mgetty.o;vgetty.o;g' >>depend ;\
		fi ;\
		\
		cd .. ;\
	done

distrib:
	echo "0" >.patchlevel
	cd .. ;\
	$(MAKE) clean
	$(MAKE) version
	$(MAKE) depend
	$(MAKE) .filelist
	cd .. ;\
	cvs commit ;\
	tar czvvf voice.tar.gz \
	 `cat voice/.filelist | awk '{ printf "voice/%s ", $$1 }' -` ;\
	$(MAKE) clean ;\
	DATE=`date +"%d%b%y"` ;\
	$(CP) voice.tar.gz /home/marc/Archiv/src/vgetty/vgetty-$$DATE.tar.gz ;\
	cvs tag "vgetty-$$DATE" ;\
	echo vgetty-$$DATE >voice/.last_release ;\
	$(RM) -f voice.tar.gz

patch:
	LAST_RELEASE=`cat .last_release` ;\
	PATCH=`cat .patchlevel` ;\
	if [ "$$PATCH" -eq 0 ]; then \
		LAST_TAG="$$LAST_RELEASE" ;\
	else \
		LAST_TAG="$$LAST_RELEASE-patch-$$PATCH" ;\
	fi ;\
	let PATCH=$$PATCH+1;\
	NEW_TAG="$$LAST_RELEASE-patch-$$PATCH" ;\
	echo $$PATCH >.patchlevel ;\
	cd .. ;\
	$(MAKE) clean ;\
	cd voice ;\
	$(MAKE) version ;\
	$(MAKE) depend ;\
	$(MAKE) .filelist ;\
	cd .. ;\
	cvs commit ;\
	cd voice ;\
	cvs rdiff -u -kk -r "$$LAST_TAG" mgetty/voice | grep -v "^Index: " \
	 > $$NEW_TAG ;\
	joe $$NEW_TAG ;\
	gzip -9 $$NEW_TAG ;\
	cvs tag "$$NEW_TAG" ;\
	cd .. ;\
	$(MAKE) clean ;\
	joe voice/Announce.patch ;\
	cp voice/Announce.patch voice/$$NEW_TAG.gz.txt ;\
	send_file nepomuk\!poseidon voice/$$NEW_TAG.gz.txt \
         ~marc/uucp/vgetty-patches ;\
	send_file nepomuk\!poseidon voice/$$NEW_TAG.gz \
	 ~marc/uucp/vgetty-patches ;\
	$(MV) voice/$$NEW_TAG.gz /home/marc/Archiv/src/vgetty

.filelist:
	@for i in contrib doc mvm Perl ;\
	do \
		generate_files.sh $$i ;\
	done
	@(for i in `find . -name .files -print` ;\
	do \
		cat $$i | sed -e 's;^;'`dirname $$i`'/;' | sed -e 's;^./;;' ;\
	done) | sort >.filelist

.PHONY: .filelist

test:
	$(MAKE) clean
	$(MAKE) version
	$(MAKE) depend
	$(MAKE) .filelist
	@find . -type f | grep -v "CVS" | cut -b3- | sort >.filelist.real
	@diff -u .filelist .filelist.real | grep -v "^---" | grep "^-" | \
	 grep -v ".filelist" >.files.missing ;\
	diff -u .filelist .filelist.real | grep -v "^+++" | grep "^+" | \
	 grep -v ".filelist" >.files.additional ;\
	(\
	if [ -s .files.missing ] ; then \
		echo "* Missing files:" ;\
		echo "" ;\
		cat .files.missing ;\
		echo "" ;\
	fi ;\
	if [ -s .files.additional ] ; then \
		echo "* Additional files:" ;\
		echo "" ;\
		cat .files.additional ;\
	fi ;\
	) >file.report ;\
	$(RM) -f .filelist.real .files.missing .files.additional ;\
	less file.report
	@rm file.report .filelist
	@find . -type f | grep -v CVS | sed -e 's#^./##g' | sort > filelist.real
	@cvs stat 2>/dev/null | grep Repos | cut -d/ -f6- | \
	 sed -e 's/,v$$//g' | sort > filelist.cvs
	@diff -u filelist.cvs filelist.real > file.report ;\
	less file.report
	@rm file.report filelist.cvs filelist.real

commit:
	cd .. ;\
	$(MAKE) clean
	$(MAKE) version
	$(MAKE) depend
	cd .. ;\
	cvs commit

clean: local-clean

local-clean:
	@$(RM) -f .filelist depend file.report include/version.h
