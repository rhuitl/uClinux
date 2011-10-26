PYTHON_PKG = Python-2.6.5
HOSTCONFVARS = CC= CXX= LD= AR= RANLIB= CPPFLAGS= CFLAGS= LDFLAGS=
HOSTCONFOPTS = --disable-shared
HOSTBUILDVARS = EXTRA_CFLAGS=
HOSTBUILDDIR = $(shell pwd)/build/$(PYTHON_PKG)/hostbuild
INSTALLDIR = $(shell pwd)/build/$(PYTHON_PKG)-install
HOSTPYTHON=$(HOSTBUILDDIR)/python
HOSTPGEN=$(HOSTBUILDDIR)/Parser/pgen
$(PYTHON_PKG)_URL = http://www.python.org/ftp/python/2.6.5/Python-2.6.5.tar.bz2
$(PYTHON_PKG)_AUTOCONF = autoconf
$(PYTHON_PKG)_CONFIGURE = ../configure
$(PYTHON_PKG)_BUILDVARS = HOSTPYTHON=$(HOSTPYTHON) HOSTPGEN=$(HOSTPGEN)
$(PYTHON_PKG)_BUILDDIR = $(PYTHON_PKG)/build
AUTOMAKE_y += $(PYTHON_PKG)

SETUPTOOLS_PKG = setuptools-0.6c11
$(SETUPTOOLS_PKG)_URL = http://pypi.python.org/packages/source/s/setuptools/setuptools-0.6c11.tar.gz

AUTOMAKE_ROMFS = python_romfs

include $(ROOTDIR)/tools/automake.inc

export PYTHON_DISABLE_MODULES=bsddb185 dl imageop sunaudiodev _bsddb _curses _curses_panel _ctypes _sqlite3 _tkinter dbm gdbm nis readline

BIN_FILES = python
PY_FILES =
SO_FILES =

# site.py and its dependencies, not needed with 'python -S' option
PY_FILES += site.py \
	os.py \
	posixpath.py \
	stat.py \
	genericpath.py \
	warnings.py \
	linecache.py \
	types.py \
	UserDict.py \
	_abcoll.py \
	abc.py \
	copy_reg.py \

# Modules needed to run setup.py when installing a distutil package
DISTUTIL_MODULES = \
	'unicodedata unicodedata.c' \
	'time timemodule.c' \
	'math mathmodule.c' \
	'binascii binascii.c' \
	'_random _randommodule.c' \
	'_struct _struct.c' \
	'cStringIO cStringIO.c' \
	'operator operator.c' \
	'_functools _functoolsmodule.c' \
	'_collections _collectionsmodule.c' \
	'_md5 md5module.c md5.c' \
	'_sha shamodule.c' \
	'_sha256 sha256module.c' \
	'_sha512 sha512module.c' \
	'array arraymodule.c' \
	'_socket socketmodule.c' \
	'zlib zlibmodule.c -I$$(prefix)/include -L$$(exec_prefix)/lib -lz' \

HOST_MODULES =

# This successfully installs the easy_install command, but running the
# easy_install command itself isn't working yet
#HOST_MODULES += $(DISTUTIL_MODULES)
#all: build/$(SETUPTOOLS_PKG)-distutil
#$(eval $(call download_dep,$(SETUPTOOLS_PKG)))

.PRECIOUS: $(addprefix build/,$(addsuffix -hostconfigured,$(AUTOMAKE_y)))
.PRECIOUS: $(addprefix build/,$(addsuffix -hostmodules,$(AUTOMAKE_y)))
.PRECIOUS: $(addprefix build/,$(addsuffix -hostbuilt,$(AUTOMAKE_y)))

build/%-hostconfigured: build/%-patched
	mkdir -p $(HOSTBUILDDIR); \
	cd $(HOSTBUILDDIR); \
	$(HOSTCONFVARS) \
	sh $($*_CONFIGURE) $(HOSTCONFOPTS)
	touch $@

build/%-hostmodules: build/%-hostconfigured
	echo -n "" >  $(HOSTBUILDDIR)/Modules/Setup.local
	for module in $(HOST_MODULES) ; do \
		echo $${module} >> $(HOSTBUILDDIR)/Modules/Setup.local; \
	done
	touch $@

build/%-hostbuilt: build/%-hostmodules
	$(HOSTBUILDVARS) \
	$(MAKE) -C $(HOSTBUILDDIR) python Parser/pgen
	touch $@

build/$(PYTHON_PKG)-built: build/$(PYTHON_PKG)-hostbuilt

build/%-distutil: build/%-patched build/$(PYTHON_PKG)-installed
	cd build/$(if $($*_BUILDDIR),$($*_BUILDDIR),$*); \
	PYTHONHOME=$(INSTALLDIR) $(HOSTPYTHON) setup.py install --prefix=$(INSTALLDIR)
	touch $@

#build/Pylons:
#	cd $(INSTALLDIR); \
#	PYTHONHOME=$(INSTALLDIR) $(HOSTPYTHON) bin/easy_install -O1 'Pylons==0.9.7'
#	touch $@

python_romfs:
	for file in $(BIN_FILES) ; do $(ROMFSINST) -d $(INSTALLDIR)/bin/$$file /bin/$$file || exit 1; done
	for file in $(PY_FILES) ; do $(ROMFSINST) -d $(INSTALLDIR)/lib/python2.6/$${file}o /lib/python2.6/$${file}o || exit 1; done
	mkdir -p $(ROMFSDIR)/lib/python2.6/lib-dynload
	for file in $(SO_FILES) ; do $(ROMFSINST) -d $(INSTALLDIR)/lib/python2.6/lib-dynload/$${file} /lib/python2.6/lib-dynload/$${file} || exit 1; done
	#$(ROMFSINST) $(INSTALLDIR)/lib/python2.6/site-packages /lib/python2.6/site-packages
