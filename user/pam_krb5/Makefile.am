EXTRA_DIST = pam_krb5.spec TODO README README.heimdal-pkinit README.mit-pkinit README.winbind

CONFIGURE_DEPENDENCIES = $(top_srcdir)/pam_krb5.spec

SUBDIRS = src tests po

VERSION=$(shell rpm -q --specfile $(top_srcdir)/pam_krb5.spec --qf '%{version}\n' | head -n1)
RELEASE=$(shell rpm -q --specfile $(top_srcdir)/pam_krb5.spec --qf '%{release}\n' | head -n1)
GITTAG=pam_krb5-$(shell rpm -q --specfile $(top_srcdir)/pam_krb5.spec --qf '%{version}-%{release}\n' --define 'dist %{nil}' | head -n1)
distdir=$(shell rpm -q --specfile --qf '%{name}-%{version}-%{release}\n' --define 'dist %{nil}' $(top_srcdir)/pam_krb5.spec | head -n1)
DISTCLEANFILES = tests/kdc/krb5cc_* tests/kdc/tkt*

tag:
	git tag $(GITTAG)

force-tag:
	git tag -f $(GITTAG)

ORIGIN=$(shell git config remote.origin.url 2> /dev/null || /bin/pwd)
ARCHIVEOUTDIR=$(shell cd $(top_srcdir) && pwd)

local-archive:
	$(MAKE) archive ORIGIN=$(ARCHIVEOUTDIR)

archive:
	repo=`pwd`; \
	tmpdir=`mktemp -d /tmp/make_archive_XXXXXX`; \
	if test -d "$$tmpdir" ; then \
		git clone $(ORIGIN) $$tmpdir/pam_krb5;\
		cd $$tmpdir/pam_krb5;\
		git checkout $(GITTAG);\
		./autogen;\
		make dist;\
		mkdir -p $$tmpdir/rpm-build-top;\
		rpmbuild \
			--define "_topdir $$tmpdir/rpm-build-top" \
			--define "_sourcedir $$tmpdir/rpm-build-top" \
			--define "_specdir $$tmpdir/rpm-build-top" \
			--define "_builddir $$tmpdir/rpm-build-top" \
			--define "_srpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			--define "_rpmdir $$tmpdir/rpm-build-top" \
			-tb $(distdir).tar.gz;\
		cp -v $(distdir).tar.gz $(ARCHIVEOUTDIR)/;\
		rm -fr $$tmpdir;\
	fi

ACLOCAL_AMFLAGS = -I m4
