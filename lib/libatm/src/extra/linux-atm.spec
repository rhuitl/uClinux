Summary: linux-atm - Tools to support ATM networking under Linux.
Name: linux-atm
%define linux_atm_version 2.4.0
%define lib_current 1
%define lib_age 0
%define lib_revision 0
Version: %{linux_atm_version}
%define includedir /usr/include
Release: 1
License: BSD License, GNU General Public License (GPL), GNU Lesser General Public License (LGPL)
Group: System Environment/Daemons
ExclusiveOS: Linux
BuildRoot: /var/tmp/%{name}-buildroot
%define _sourcedir %(pwd)
%define _specdir %(pwd)/src/extra
%define _rpmdir %(pwd)/src/extra/RPMS
%define _srcrpmdir %(pwd)/src/extra/SRPMS
Source: linux-atm-%{linux_atm_version}.tar.gz


%description
Tools to support ATM networking under Linux.  Eventually this will also include
support for some types of DSL modems.

%prep
%setup -q

%build
./configure
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/local/include
install -c -m 644 src/include/atm.h $RPM_BUILD_ROOT/usr/local/include
install -c -m 644 src/include/atmd.h $RPM_BUILD_ROOT/usr/local/include
install -c -m 644 src/include/atmsap.h $RPM_BUILD_ROOT/usr/local/include
mkdir -p $RPM_BUILD_ROOT/usr/local/lib
install -c -m 755 src/lib/.libs/libatm.so.%{lib_current}.%{lib_age}.%{lib_revision} $RPM_BUILD_ROOT/usr/local/lib/libatm.so.%{lib_current}.%{lib_age}.%{lib_revision}
ln -s libatm.so.%{lib_current}.%{lib_age}.%{lib_revision} $RPM_BUILD_ROOT/usr/local/lib/libatm.so.%{lib_current}
ln -s libatm.so.%{lib_current}.%{lib_age}.%{lib_revision} $RPM_BUILD_ROOT/usr/local/lib/libatm.so
install -c -m 755 src/lib/.libs/libatm.lai $RPM_BUILD_ROOT/usr/local/lib/libatm.la
install -c -m 644 src/lib/.libs/libatm.a $RPM_BUILD_ROOT/usr/local/lib
ranlib $RPM_BUILD_ROOT/usr/local/lib/libatm.a
mkdir -p $RPM_BUILD_ROOT/usr/local/bin
install -c -m 755 src/test/.libs/aread $RPM_BUILD_ROOT/usr/local/bin
install -c -m 755 src/test/.libs/awrite $RPM_BUILD_ROOT/usr/local/bin
install -c -m 755 src/test/.libs/ttcp_atm $RPM_BUILD_ROOT/usr/local/bin
mkdir -p $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 755 src/sigd/.libs/atmsigd $RPM_BUILD_ROOT/usr/local/sbin
mkdir -p $RPM_BUILD_ROOT/usr/local/etc
install -c -m 644 src/sigd/atmsigd.conf $RPM_BUILD_ROOT/usr/local/etc
mkdir -p $RPM_BUILD_ROOT/usr/local/man/man4
install -c -m 644 src/sigd/atmsigd.conf.4 $RPM_BUILD_ROOT/usr/local/man/man4
mkdir -p $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 644 src/sigd/atmsigd.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 755 src/maint/.libs/atmdiag $RPM_BUILD_ROOT/usr/local/bin
install -c -m 755 src/maint/.libs/atmdump $RPM_BUILD_ROOT/usr/local/bin
install -c -m 755 src/maint/.libs/sonetdiag $RPM_BUILD_ROOT/usr/local/bin
install -c -m 755 src/maint/.libs/saaldump $RPM_BUILD_ROOT/usr/local/bin
install -c -m 755 src/maint/.libs/atmaddr $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 755 src/maint/.libs/esi $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 755 src/maint/.libs/atmloop $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 755 src/maint/.libs/atmtcp $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 755 src/maint/.libs/enitune $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 755 src/maint/.libs/zntune $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 644 src/maint/atmaddr.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 644 src/maint/atmdiag.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 644 src/maint/atmdump.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 644 src/maint/atmloop.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 644 src/maint/atmtcp.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 644 src/maint/esi.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 755 src/arpd/.libs/atmarp $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 755 src/arpd/.libs/atmarpd $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 644 src/arpd/atmarp.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 644 src/arpd/atmarpd.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 755 src/ilmid/.libs/ilmid $RPM_BUILD_ROOT/usr/local/sbin
mkdir -p $RPM_BUILD_ROOT/usr/local/man/man7
install -c -m 644 src/man/qos.7 $RPM_BUILD_ROOT/usr/local/man/man7
install -c -m 644 src/man/sap.7 $RPM_BUILD_ROOT/usr/local/man/man7
install -c -m 755 src/led/.libs/zeppelin $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 644 src/led/zeppelin.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 755 src/lane/.libs/les $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 644 src/lane/les.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 755 src/lane/.libs/bus $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 644 src/lane/bus.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 755 src/lane/.libs/lecs $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 644 src/lane/lecs.8 $RPM_BUILD_ROOT/usr/local/man/man8
install -c -m 755 src/mpoad/.libs/mpcd $RPM_BUILD_ROOT/usr/local/sbin
install -c -m 644 src/mpoad/mpcd.8 $RPM_BUILD_ROOT/usr/local/man/man8
mkdir -p $RPM_BUILD_ROOT/etc
install -c -m 644 src/config/hosts.atm $RPM_BUILD_ROOT/etc

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)
%doc AUTHORS BUGS ChangeLog COPYING COPYING.GPL COPYING.LGPL
%doc INSTALL NEWS README THANKS
%doc doc/ src/config/init-redhat/ src/extra/ANS src/extra/drivers
/usr/local/include/atm.h
/usr/local/include/atmd.h
/usr/local/include/atmsap.h
/usr/local/lib/libatm.so.%{lib_current}.%{lib_age}.%{lib_revision}
/usr/local/lib/libatm.so.%{lib_current}
/usr/local/lib/libatm.so
/usr/local/lib/libatm.la
/usr/local/lib/libatm.a
/usr/local/bin/aread
/usr/local/bin/awrite
/usr/local/bin/ttcp_atm
/usr/local/sbin/atmsigd
%config /usr/local/etc/atmsigd.conf
/usr/local/man/man4/atmsigd.conf.4
/usr/local/man/man8/atmsigd.8
/usr/local/bin/atmdiag
/usr/local/bin/atmdump
/usr/local/bin/sonetdiag
/usr/local/bin/saaldump
/usr/local/sbin/atmaddr
/usr/local/sbin/esi
/usr/local/sbin/atmloop
/usr/local/sbin/atmtcp
/usr/local/sbin/enitune
/usr/local/sbin/zntune
/usr/local/man/man8/atmaddr.8
/usr/local/man/man8/atmdiag.8
/usr/local/man/man8/atmdump.8
/usr/local/man/man8/atmloop.8
/usr/local/man/man8/atmtcp.8
/usr/local/man/man8/esi.8
/usr/local/sbin/atmarp
/usr/local/sbin/atmarpd
/usr/local/man/man8/atmarp.8
/usr/local/man/man8/atmarpd.8
/usr/local/sbin/ilmid
/usr/local/man/man7/qos.7
/usr/local/man/man7/sap.7
/usr/local/sbin/zeppelin
/usr/local/man/man8/zeppelin.8
/usr/local/sbin/les
/usr/local/sbin/bus
/usr/local/sbin/lecs
/usr/local/man/man8/les.8
/usr/local/man/man8/bus.8
/usr/local/man/man8/lecs.8
/usr/local/sbin/mpcd
/usr/local/man/man8/mpcd.8
%config /etc/hosts.atm

%post
ldconfig -n /usr/local/lib

%postun
ldconfig -n /usr/local/lib

%changelog
* Fri Sep 14 2001 Paul Schroeder <paulsch@@us.ibm.com>
- First build of linux-atm RPM.


