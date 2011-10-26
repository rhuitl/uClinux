%define name speedtouch
%define version 1.3
%define release 2

Summary: ALCATEL SpeedTouch USB ADSL modem user-space driver
Name: %{name}
Version:%{version}
Release: %{release}
Source: http://speedtouch.sf.net/speedtouch-%{version}.tar.gz
URL: http://speedtouch.sf.net
Copyright: GPL
Group: System/Kernel and hardware
Prefix: %{_prefix}
BuildRoot: %{_builddir}/%{name}-build
Requires: ppp

%description
ALCATEL SpeedTouch USB ADSL modem user-space driver. This package contains 
all the necessary software to use your SpeedTouch USB modem under Linux. It
currently support only PPPoA encapsulation.

%prep
%setup

%build
%configure --enable-install=$USER 
%make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_bindir}/speedtouch-setup
%{_bindir}/speedtouch-start
%{_bindir}/speedtouch-stop
%{_sbindir}/modem_run
%{_sbindir}/pppoa2
%{_sbindir}/pppoa3
%{_sysconfdir}/hotplug/usb/speedtouch
%{_sysconfdir}/hotplug/usb/speedtouch.usermap
/usr/share/speedtouch/boot.v123.bin
%doc /usr/share/doc/speedtouch/
%doc %{_mandir}/man1/speedtouch-setup.1.bz2
%doc %{_mandir}/man1/speedtouch-start.1.bz2
%doc %{_mandir}/man1/speedtouch-stop.1.bz2
%doc %{_mandir}/man8/modem_run.8.bz2
%doc %{_mandir}/man8/pppoa2.8.bz2
%doc %{_mandir}/man8/pppoa3.8.bz2
%dir %{_sysconfdir}/speedtouch

%changelog
* Mon May 24 2004 Benoit PAPILLAULT <benoit.papillault@free.fr> Updated for the 1.3 release. Not tested.
* Tue Mar 16 2004 Benoit PAPILLAULT <benoit.papillault@free.fr> Updated for 1.2 release. Tested on Mandrake.
* Mon Mar 11 2002 Alex Bennee <alex@bennee.com> First working version (?for 1.1 release)
* Mon Apr  9 2001 Benoit PAPILLAULT <benoit.papillault@free.fr> VERSION-1mdk
- 


# end of file
