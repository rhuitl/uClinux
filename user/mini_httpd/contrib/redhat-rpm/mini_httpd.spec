Summary: small, simple http daemon, supports SSL
Name: mini_httpd
Version: 1.14
Release: 1
Copyright: Freely Redistributable
Packager: Bennett Todd <bet@mordor.net>
Group: Networking/Daemons
URL: http://www.acme.com/software/mini_httpd/
Source: http://www.acme.com/software/mini_httpd-%{PACKAGE_VERSION}.tar.gz
BuildRoot: /var/tmp/mini_httpd-rpmbuild
Requires: openssl
%description

Simple and small HTTP daemon supporting SSL

%prep
%setup

%build
make SSL_INCDIR=/usr/include/openssl \
     SSL_LIBDIR=/usr/lib \
     SSL_DEFS=-DUSE_SSL \
     SSL_INC=-I/usr/include/openssl \
     SSL_LIBS='-lssl -lcrypto' \
     BINDIR=/usr/bin \
     MANDIR=/usr/man \
     CFLAGS='-g -DUSE_SSL -I/usr/include/openssl'

%install
mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/man/man1
mkdir -p $RPM_BUILD_ROOT/usr/man/man8
mkdir -p $RPM_BUILD_ROOT/home/httpd/html
make BINDIR=$RPM_BUILD_ROOT/usr/bin \
     MANDIR=$RPM_BUILD_ROOT/usr/man \
     install
install index.html $RPM_BUILD_ROOT/home/httpd/html
install contrib/redhat-rpm/mini_httpd.init \
	$RPM_BUILD_ROOT/etc/rc.d/init.d/mini_httpd

%post
/sbin/chkconfig mini_httpd reset

%preun
/etc/rc.d/init.d/mini_httpd stop
/sbin/chkconfig --level 0123456 mini_httpd off

%files
%defattr(-,root,root)

/usr/bin/*
/home/httpd/html/index.html
%attr(0755,root,root) /etc/rc.d/init.d/mini_httpd
%doc /usr/man/*/*
%doc [A-Z]*


%changelog
* Thu Jun 15 2000 <jef@acme.com> Version 1.14
* Fri May 26 2000 <jef@acme.com> Version 1.13
* Wed Mar 01 2000 <jef@acme.com> Version 1.12
* Sun Feb 06 2000 <jef@acme.com> Version 1.11
* Wed Feb 02 2000 <jef@acme.com> Version 1.10
* Mon Jan 31 2000 <bet@rahul.net> Version 1.09, added init script
* Wed Jan 19 2000 <bet@rahul.net> Version 1.08, reset release to 1
* Mon Dec 13 1999 <bet@mordor.net>
  - Added defattr to %files, bumped Release to 2
* Sat Dec 11 1999 <bet@mordor.net>
  - Bumped version to 19991210, switched source from oct to dec
* Fri Dec 10 1999 <bet@mordor.net>
  - Initial Wrap
