# $Id: ipmasqadm-0.4.spec,v 1.4 1998/12/04 23:03:54 jjo Exp jjo $
Summary: ipmasqadm utility
Name: ipmasqadm
%define version 0.4.2
Version: %{version}
Release: 1
Packager: Juan Jose Ciarlante <irriga@impsat1.com.ar>
Copyright: distributable
Group: Networking/Admin
Source: http://juanjox.home.ml.org/ipmasqadm-%{version}.tar.gz
BuildRoot: /tmp/ipmasqadm-root
%description
This tool allows ipmasq addtional setup, it is needed if you 
want to activate port forwarding or auto forwarding in 2.1 kernels.

%prep
%setup 

%build
make "RPM_OPT_FLAGS=$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/sbin 
mkdir -p $RPM_BUILD_ROOT/usr/lib/ipmasqadm
chmod 700 $RPM_BUILD_ROOT/usr/lib/ipmasqadm
make DESTDIR=$RPM_BUILD_ROOT install

chmod 755 $RPM_BUILD_ROOT/usr/sbin/ipmasqadm
strip $RPM_BUILD_ROOT/usr/sbin/ipmasqadm

%clean
rm -rf $RPM_BUILD_ROOT


%files
%doc doc/* ChangeLog
/usr/man/man8/ipmasqadm.8
/usr/sbin/ipmasqadm
%dir /usr/lib/ipmasqadm
/usr/lib/ipmasqadm/portfw.so
/usr/lib/ipmasqadm/autofw.so
/usr/lib/ipmasqadm/mfw.so
