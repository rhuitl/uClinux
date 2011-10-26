###############################################################################
#
# General
#
###############################################################################

Name: dnsmasq
Version: 1.18
Release: 1
Copyright: GPL
Group: Productivity/Networking/DNS/Servers
Vendor: Simon Kelley
Packager: Simon Kelley
URL: http://www.thekelleys.org.uk/dnsmasq
Provides: dns_daemon
Conflicts: bind bind8 bind9
PreReq: %fillup_prereq %insserv_prereq
Autoreqprov: on
Source0: %{name}-%{version}.tar.bz2
BuildRoot: /var/tmp/%{name}-%{version}
Summary: A lightweight caching nameserver

%description
Dnsmasq is lightweight, easy to configure DNS forwarder designed to provide DNS (domain name) services to a small network where using BIND would be overkill. It can be have its DNS servers automatically configured by PPP or DHCP, and it can serve the names of local machines which are not in the global DNS. It is ideal for networks behind NAT routers and connected via modem, ISDN, ADSL, or cable-modem connections. 


###############################################################################
#
# Build
#
###############################################################################

%prep
%setup -q
%build
%{?suse_update_config:%{suse_update_config -f}}
make

###############################################################################
#
# Install
#
###############################################################################

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p ${RPM_BUILD_ROOT}/etc/init.d
mkdir -p ${RPM_BUILD_ROOT}/usr/sbin
mkdir -p ${RPM_BUILD_ROOT}%{_mandir}/man8
install -o root -g root -m 755 rpm/rc.dnsmasq-suse8x $RPM_BUILD_ROOT/etc/init.d/dnsmasq
install -o root -g root -m 644 rpm/dnsmasq.conf.sample $RPM_BUILD_ROOT/etc/dnsmasq.conf
strip dnsmasq
install -o root -g root -m 755 dnsmasq $RPM_BUILD_ROOT/usr/sbin
ln -sf ../../etc/init.d/dnsmasq $RPM_BUILD_ROOT/usr/sbin/rcdnsmasq
gzip -9 dnsmasq.8
install -o root -g root -m 644 dnsmasq.8.gz $RPM_BUILD_ROOT%{_mandir}/man8

###############################################################################
#
# Clean up
#
###############################################################################

%clean
rm -rf $RPM_BUILD_ROOT

###############################################################################
#
# Post-install scriptlet
#
###############################################################################

%post
%{fillup_and_insserv dnsmasq}

###############################################################################
#
# Post-uninstall scriptlet
#
# The %postun script executes after the package has been removed. It is the
# last chance for a package to clean up after itself.
#
###############################################################################

%postun
%{insserv_cleanup}

###############################################################################
#
# File list
#
###############################################################################

%files
%defattr(-,root,root)
%doc CHANGELOG COPYING FAQ doc.html setup.html rpm/dnsmasq.conf.sample
%config /etc/init.d/dnsmasq
%config /etc/dnsmasq.conf
/usr/sbin/rcdnsmasq
/usr/sbin/dnsmasq
%doc %{_mandir}/man8/dnsmasq.8.gz



