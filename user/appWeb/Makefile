#
#	Makefile -- Top level Makefile. 
#
#	Copyright (c) Mbedthis Software LLC, 2003-2004. All Rights Reserved.
#
#	Standard Make targets supported are:
#	
#		make 						# Does a "make compile"
#		make clean					# Removes generated objects
#		make compile				# Compiles the source
#		make depend					# Generates the make dependencies
#		make test 					# Runs unit tests
#		make package				# Creates an installable package
#		make projects				# Creates Visual Studio project files
#
#	Additional targets for this makefile:
#
#		make build					# Do a clean build
#		make install				# Call install-binary
#		make install-release		# Install release files (README.TXT etc)
#		make install-binary			# Install binary files
#		make install-dev			# Install development libraries and headers
#		make install-doc			# Install documentation
#		make install-samples		# Install samples
#		make install-source			# Install source code
#		make romfs					# Make a package for Uclibc romfs
#
#	If it is a first time build (or if conf/config.cache does not exist)
#	configure will be run. Care is taken to build the bootstrap utilities
#	first. 
#

BUILD_CHECK	:= buildCheck
FIRST		:= first

include 	make.dep

PRE_DIRS	= $(BLD_DIRS)

buildCheck: conf/config.cache

#
#	Complete build for first time builds and rebuilds
# 
conf/config.cache: config.make
	@. config.sh ; echo -ne "    # Building $(BLD_PRODUCT) " ; \
	echo -e "$(BLD_VERSION)-$${BLD_NUMBER}, ${BLD_TYPE} Build"
	@echo "    ./configure"
	@./configure
	@echo "    $(MAKE) -S clean"
	@$(MAKE) --no-print-directory -S clean
	@echo "    $(MAKE) -S -C bootstrap compile"
	@$(MAKE) --no-print-directory -S -C bootstrap compile
	@echo "    $(MAKE) -S depend"
	@$(MAKE) --no-print-directory -S depend

#
#	uClinux primary make target -- Copy the uClinux defaults to be the
#	factory defaults (conf/config.defaults).
#
#	This is needed because uClinux will pass in the cross compiler settings
#	in CFLAGS, IFLAGS, LDFLAGS, CC, AR, LD and RANLIB. Configure will listen
#	to these settings and save them in config.cache for subsequent use.
#
config.make: dummy
	@if [ "$(UCLINUX_BUILD_USER)" = 1 ] ; \
	then \
		rm -f conf/config.defaults ; \
		echo "    ln -s $(BLD_PRODUCT)/uclinux.defaults conf/config.defaults" ;\
		ln -s $(BLD_PRODUCT)/uclinux.defaults conf/config.defaults ; \
		if [ ! -f conf/config.cache -o ../../.config -nt config.make ] ; \
		then \
			if [ "$$CONFIG_USER_APPWEB_DYNAMIC" = "y" ] ; \
			then \
				SW="$$SW --enable-modules \
					--with-auth=loadable \
					--with-cgi=loadable \
					--with-copy=loadable \
					--with-esp=loadable \
					--with-copy=loadable" ; \
				moduleType=loadable ; \
			else \
				SW="$$SW --disable-modules" ; \
				moduleType=builtin ; \
			fi ; \
			if [ "$$CONFIG_USER_APPWEB_MULTITHREAD" = "y" ] ; \
			then \
				SW="$$SW --enable-multi-thread" ; \
			else SW="$$SW --disable-multi-thread" ; \
			fi ; \
			if [ "$$CONFIG_USER_APPWEB_SSL" = "y" ] ; \
			then \
				SW="$$SW --with-openssl=$$moduleType" ; \
				SW="$$SW --with-openssl-dir=../../lib/libssl" ; \
			else SW="$$SW --without-ssl" ; \
			fi ; \
			if [ "$$CONFIG_USER_APPWEB_CGI" = "y" ] ; \
			then SW="$$SW --with-cgi=$$moduleType" ; \
			else SW="$$SW --without-cgi" ; \
			fi ; \
			echo "    ./configure $$SW " ; \
			./configure $$SW; \
		fi ; \
	fi

#
#	uClinux target to package the build into the ROM file system
#
romfs:
	@if [ "$(ROMFSDIR)" = "" ] ; \
	then \
		echo "ROMFSDIR is not defined" ; \
		exit 255 ; \
	fi
	@PKG_DIR=$(ROMFSDIR) SKIP_PERMS=1 \
		$(BLD_PRODUCT)/package/$(BLD_OS)/makeInstall binary

#
#	Installation targets
#
install: install-rootCheck install-binary

install-rootCheck:
	@if [ $(BLD_OS) != WIN -a `id -u` -ne 0 ] ; \
	then \
		echo "Must be root to install" ; \
		exit 255 ; \
	fi

install-release: install-rootCheck
	@$(BLD_PRODUCT)/package/$(BLD_OS)/makeInstall release

install-binary: install-rootCheck
	@$(BLD_PRODUCT)/package/$(BLD_OS)/makeInstall binary
	@echo -e "    #\n    # To start ${BLD_NAME}, run as root:\n    #"
	@echo -e "        service ${BLD_PRODUCT} start\n"

install-dev: install-rootCheck
	@$(BLD_PRODUCT)/package/$(BLD_OS)/makeInstall dev

install-doc: install-rootCheck
	@$(BLD_PRODUCT)/package/$(BLD_OS)/makeInstall doc

install-samples: install-rootCheck
	@$(BLD_PRODUCT)/package/$(BLD_OS)/makeInstall samples

install-source: install-rootCheck
	@$(BLD_PRODUCT)/package/$(BLD_OS)/makeInstall source

install-all: install-rootCheck
	@$(BLD_PRODUCT)/package/$(BLD_OS)/makeInstall \
		"release binary dev doc samples source"

uninstall: install-rootCheck
	@$(BLD_PRODUCT)/package/$(BLD_OS)/makeUninstall

#
#	Standard alias for test
#
check:
	echo "    $(MAKE) -S $(MAKEF) test" ; \
	$(MAKE) --no-print-directory -S $(MAKEF) test; \

#
#	Target for a new build. Used internally by Mbedthis.
#
build:  conf/config.cache
	@(  \
		[ -x bin/incBuild -a -f mbedthis ] && bin/incBuild ; . config.sh ; \
		touch config.make ; \
		echo "    $(MAKE) -S compile test" ; \
		$(MAKE) --no-print-directory -S compile test; \
		echo -ne "\n    #\n    # Build Complete. Built $(BLD_PRODUCT) " ; \
		echo -e "$(BLD_VERSION)-$${BLD_NUMBER}, ${BLD_TYPE} Build" ; \
		echo -e "    # Build log saved in make.log\n    #" ; \
	) 2>&1 | tee make.log

#
#	Crude check if AppWeb has been removed
#
verifyClean:
	@echo /etc/appWeb* /usr/lib/appWeb* /sbin/appWeb* /usr/sbin/appWeb* \
		/usr/src/appWeb* /usr/share/appWeb* /var/appWeb*

compileExtra: make.os

make.os: conf/make.os.${BLD_OS}
	@rm -f make.os
	@echo "    cp conf/make.os.${BLD_OS} make.os"
	@cp conf/make.os.${BLD_OS} make.os
	@chmod 644 make.os

#
#	Linux gdb has trouble debugging dynamically loadable DLLs
#
debugConf:
	@CC="ccache cc" \
		./configure --reset --type=DEBUG --disable-modules --enable-static 

uclibc:
	DIR=/usr/local ; \
	export CC=i386-linux-uclibc-gcc ; \
	GCC_DIR=`$$CC -print-libgcc-file-name 2>&1 | sed -e 's/\/libgcc.a//'` ; \
	AR=i386-linux-uclibc-ar \
	LD=i386-linux-uclibc-ld \
	RANLIB=i386-linux-uclibc-ranlib \
	CFLAGS= \
	IFLAGS="-I$$DIR/i386-linux-uclibc/include -I$$GCC_DIR/include" \
	LDFLAGS="\
		-L$$GCC_DIR/lib \
		-L$$DIR/i386-linux-uclibc/lib \
		-Wl,--dynamic-linker -Wl,$$DIR/i386-linux/lib/ld-uClibc.so.0" \
	./configure  --reset --type=DEBUG --without-php --disable-modules

#
#	CFLAGS="-nostdinc -nostdinc++"
#	LDFLAGS"=-nostdlib --dynamic-linker $DIR/lib/ld-uClibc.so.0 \
#		--rpath-link $DIR/lib $DIR/lib/crt0.o"
## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
