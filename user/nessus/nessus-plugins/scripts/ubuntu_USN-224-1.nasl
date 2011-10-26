# This script was automatically generated from the 224-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- kerberos4kth-clients 
- kerberos4kth-clients-x 
- kerberos4kth-dev 
- kerberos4kth-docs 
- kerberos4kth-kdc 
- kerberos4kth-kip 
- kerberos4kth-servers 
- kerberos4kth-servers-x 
- kerberos4kth-services 
- kerberos4kth-user 
- kerberos4kth-x11 
- kerberos4kth1 
- krb5-admin-server 
- krb5-clients 
- krb5-doc 
- krb5-ftpd 
- krb5-kdc 
- krb5-rsh-server 
- krb5-telnetd 
- krb5-user 
- libkadm1-kerberos4kth 
- libkadm55 
- libkafs0-kerberos4kth 
- libkdb-
[...]

Description :

Gaël Delalleau discovered a buffer overflow in the env_opt_add()
function of the Kerberos 4 and 5 telnet clients. By sending specially
crafted replies, a malicious telnet server could exploit this to
execute arbitrary code with the privileges of the user running the
telnet client. (CVE-2005-0468)

Gaël Delalleau discovered a buffer overflow in the handling of the
LINEMODE suboptions in the telnet clients of Kerberos 4 and 5. By
sending a specially constructed reply containing a large number of SLC
(Set Local Character) commands, a remote attacker (i. e.  a malicious
telnet server) could execute arbitrary commands with the privileges of
the user running the telnet client. (CVE-2005-0469)

Daniel Wachdorf discovered two remote vulnerabilities in the Key
Distribution Center of Kerberos 5 (krb5-kdc). By sending certain TCP
connection requests, a remote attacker could trigger a double-freeing
of memory, which led to memory corruption and a crash of the KDC
server. (CVE-2005-1174). Under rare circumstances the sam
[...]

Solution :

Upgrade to : 
- kerberos4kth-clients-1.2.2-11.1ubuntu2.1 (Ubuntu 5.04)
- kerberos4kth-clients-x-1.2.2-11.1ubuntu2.1 (Ubuntu 5.04)
- kerberos4kth-dev-1.2.2-11.1ubuntu2.1 (Ubuntu 5.04)
- kerberos4kth-docs-1.2.2-11.1ubuntu2.1 (Ubuntu 5.04)
- kerberos4kth-kdc-1.2.2-11.1ubuntu2.1 (Ubuntu 5.04)
- kerberos4kth-kip-1.2.2-11.1ubuntu2.1 (Ubuntu 5.04)
- kerberos4kth-servers-1.2.2-11.1ubuntu2.1 (Ubuntu 5.04)
- kerberos4kth-servers-x-1.2.2-11.1ubuntu2.1 (Ubuntu 5.04)
- kerberos4kth-services-1.2.2-11.1ubuntu2.1 (Ubuntu 
[...]


Risk factor : High
';

if (description) {
script_id(20767);
if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0027");
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "224-1");
script_summary(english:"krb4, krb5 vulnerabilities");
script_name(english:"USN224-1 : krb4, krb5 vulnerabilities");
script_cve_id("CVE-2005-0468","CVE-2005-0469","CVE-2005-1174","CVE-2005-1175","CVE-2005-1689");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-clients", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-clients-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-clients-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-clients-x", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-clients-x-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-clients-x-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-dev", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-dev-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-docs", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-docs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-docs-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-kdc", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-kdc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-kdc-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-kip", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-kip-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-kip-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-servers", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-servers-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-servers-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-servers-x", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-servers-x-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-servers-x-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-services", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-services-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-services-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-user", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-user-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-user-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth-x11", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth-x11-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth-x11-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kerberos4kth1", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package kerberos4kth1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kerberos4kth1-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "krb5-admin-server", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-admin-server-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to krb5-admin-server-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "krb5-clients", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-clients-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to krb5-clients-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "krb5-doc", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to krb5-doc-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "krb5-ftpd", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-ftpd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to krb5-ftpd-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "krb5-kdc", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-kdc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to krb5-kdc-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "krb5-rsh-server", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-rsh-server-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to krb5-rsh-server-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "krb5-telnetd", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-telnetd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to krb5-telnetd-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "krb5-user", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package krb5-user-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to krb5-user-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkadm1-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkadm1-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkadm1-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkadm55", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkadm55-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkadm55-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkafs0-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkafs0-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkafs0-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkdb-1-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkdb-1-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkdb-1-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkrb-1-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkrb-1-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkrb-1-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkrb5-dev", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkrb5-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkrb5-dev-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkrb53", pkgver: "1.3.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkrb53-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkrb53-1.3.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libkthacl1-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkthacl1-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libkthacl1-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libotp0-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libotp0-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libotp0-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libroken16-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libroken16-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libroken16-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsl0-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libsl0-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsl0-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libss0-kerberos4kth", pkgver: "1.2.2-11.1ubuntu2.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libss0-kerberos4kth-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libss0-kerberos4kth-1.2.2-11.1ubuntu2.1
');
}

if (w) { security_hole(port: 0, data: desc); }
