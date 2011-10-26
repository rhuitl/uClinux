Summary: PAM module for LDAP.
Name: pam_ldap
Version: 179
Release: 1
Source0: ftp://ftp.padl.com/pub/%{name}-%{version}.tar.gz
Source1: ldap.conf
URL: http://www.padl.com/
Copyright: LGPL
Group: System Environment/Base
BuildRoot: %{_tmppath}/%{name}-root
BuildPrereq: openldap-devel
Requires: openldap cyrus-sasl openssl
Obsoletes: pam_ldap

%description
This package includes a LDAP access clients: pam_ldap.

Pam_ldap is a module for Linux-PAM that supports password changes, V2/V3
clients, Netscapes SSL/OpenSSL, ypldapd, Netscape Directory Server password
policies, access authorization, crypted hashes, etc.

Install nss_ldap if you need LDAP access clients.

%prep
%setup -q -a 0

%build
./configure
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/{etc,lib/security}

install -m 755 pam_ldap.so \
	       $RPM_BUILD_ROOT/lib/security/

install -m 644 %{SOURCE1} $RPM_BUILD_ROOT/etc/ldap.conf

chmod 755 $RPM_BUILD_ROOT/lib/security/*.so*

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(0755,root,root) /lib/security/*.so*
%attr(0644,root,root) %config(noreplace) /etc/ldap.conf
%doc AUTHORS NEWS COPYING COPYING.LIB README ChangeLog pam.d

%changelog
* Mon Jan 08 2001 Joe Little <jlittle@open-it.org>
- first PAM_LDAP specific RPM, stolen from the previously maintained nss_ldap

* Thu Jan 04 2001 Joe Little <jlittle@open-it.org>
- changed Makefile.RPM.openldap2 to a patch instead of a source file
- updated to pam_ldap 86 and nss_ldap 126

* Wed Jan 03 2001 Joe Little <jlittle@open-it.org>
- update to pam_ldap 84 and a change in the included Makefile to have libnss
  instead of just nss* in /usr/lib

* Tue Jan 02 2001 Joe Little <jlittle@open-it.org>
- update to pam_ldap 82 and nss_ldap 124

* Tue Dec 05 2000 Joe Little <jlittle@open-it.org>
- changed provided nss-Makefile to use dynamic lber/ldap libs; fixes nss_ldap

* Fri Oct 27 2000 Joe Little <jlittle@open-it.org>
- updated my build for nss_ldap and pam_ldap to solve race condition as told by
  Luke Howard

* Thu Oct 19 2000 Joe Little <jlittle@open-it.org>
- insured install uses openldap2 specific makefile
- fixed doc inclusion issue - which affect pam.d samples being provided

* Wed Oct 11 2000 Joe Little <jlittle@open-it.org>
- updated for latest nss/pam versions, and for building against openldap 2.x
- also added req for cyrus-sasl

* Thu Jul 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to pam_ldap 67 to fix a bug in template user code
- convert symlink in /usr/lib to a relative one (#16132)

* Thu Jul 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to nss_ldap 113 and pam_ldap 66

* Wed Jul 12 2000 Prospector <bugzilla@redhat.com>
- automatic rebuild

* Tue Jun 27 2000 Matt Wilson <msw@redhat.com>
- changed all the -,- in attr statements to root,root

* Tue Jun 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- update pam_ldap to 63

* Wed May 31 2000 Nalin Dahyabhai <nalin@redhat.com>
- update pam_ldap to 56

* Tue May 30 2000 Nalin Dahyabhai <nalin@redhat.com>
- update pam_ldap to 55
- back out no-threads patch for pam_ldap, not needed any more

* Thu May 25 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to 110
- revert prototype patch, looks like a problem with the new glibc after all

* Fri May 19 2000 Nalin Dahyabhai <nalin@redhat.com>
- get libpthread out of the NSS module
- fix prototype problems in getpwXXX()

* Mon May 15 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to nss_ldap 109

* Sat Apr 29 2000 Nalin Dahyabhai <nalin@redhat.com>
- update pam_ldap 51

* Tue Apr 25 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to nss_ldap 108 and pam_ldap 49

* Thu Apr 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to pam_ldap 48

* Thu Mar 30 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to nss_ldap 107
- note: check http://www.advogato.org/person/lukeh/ for Luke's changelog

* Tue Mar 21 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to nss_ldap 106

* Wed Feb  9 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to nss_ldap 105

* Mon Feb  7 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to nss_ldap 104 and pam_ldap 46
- disable link against libpthread in pam_ldap

* Tue Feb  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- remove migration tools, because this package requires openldap now, which
  also includes them

* Fri Jan 28 2000 Nalin Dahyabhai <nalin@redhat.com>
- update to nss_ldap 103

* Mon Jan 24 2000 Preston Brown <pbrown@redhat.com>
- fix typo in linuxconf-pair pam cfg file (#7800)

* Tue Jan 11 2000 Preston Brown <pbrown@redhat.com>
- v99, made it require pam_ldap
- added perl migration tools
- integrate pam_ldap stuff

* Fri Oct 22 1999 Bill Nottingham <notting@redhat.com>
- statically link ldap libraries (they're in /usr/lib)

* Tue Aug 10 1999 Cristian Gafton <gafton@redhat.com>
- use the ldap.conf file as an external source
- don't forcibly build the support for version 3
- imported the default spec file from the tarball and fixed it up for RH 6.1
