%define ver	1.3.20-pl0
%define rel	1
%define prefix	/usr

Summary:	DHCP Client Daemon.
Name:		dhcpcd
Version:	1.3.20pl0
Release:	%rel
Copyright:	GPL
Group:		Daemons/Networking
Source:		ftp://ftp.phystech.com/pub/%{name}-%{ver}.tar.gz
URL:		http://www.phystech.com/download
BuildRoot:	/var/tmp/%{name}-%{ver}-%{rel}-root
Packager:	Fill In As You Wish
Docdir:		%{prefix}/doc

%description
This package contains the development release of a DHCP Client 
Daemon for Linux kernels 2.0-2.3

Authors:
	Sergei Viznyuk	<sv@phystech.com>


%prep
%setup -q -n %{name}-%{ver}


%build
# Needed for snapshot releases.
if [ ! -f configure ]; then
	CFLAGS="$RPM_OPT_FLAGS" ./autogen.sh --prefix=%prefix
else
	CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix=%prefix
fi

if [ "$SMP" != "" ]; then
	JSMP	= '"MAKE=make -k -j $SMP"'
fi

make ${JSMP};


%install
[ -d ${RPM_BUILD_ROOT} ] && rm -rf ${RPM_BUILD_ROOT}

make prefix=${RPM_BUILD_ROOT}%{prefix} install-strip	\
	sysconfdir=${RPM_BUILD_ROOT}/etc
mkdir -p ${RPM_BUILD_ROOT}/etc/dhcpc


%clean
(PKGDIR=`pwd`; cd ..; rm -rf ${PKGDIR} ${RPM_BUILD_ROOT})


%files
%defattr (-, root, root)
/sbin/dhcpcd
%{prefix}/man/man8/*
%dir /etc/dhcpc
%doc AUTHORS
%doc ChangeLog
%doc COPYING
%doc INSTALL
%doc NEWS
%doc README
%doc *.lsm

