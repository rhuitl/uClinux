# This script was automatically generated from the 31-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- cyrus21-admin 
- cyrus21-clients 
- cyrus21-common 
- cyrus21-dev 
- cyrus21-doc 
- cyrus21-imapd 
- cyrus21-murder 
- cyrus21-pop3d 
- libcyrus-imap-perl21 


Description :

Stefan Esser discovered several buffer overflows in the Cyrus IMAP
server. Due to insufficient checking within the argument parser of
the "partial" and "fetch" commands, an argument like "body[p" was
detected as "body.peek". This could cause a buffer overflow which
could be exploited to execute arbitrary attacker-supplied code.

This update also fixes an exploitable buffer overflow that could be
triggered in situations when memory allocation fails (i. e. when no
free memory is available any more).

Both vulnerabilities can lead to privilege escalation to root.

Solution :

Upgrade to : 
- cyrus21-admin-2.1.16-6ubuntu0.1 (Ubuntu 4.10)
- cyrus21-clients-2.1.16-6ubuntu0.1 (Ubuntu 4.10)
- cyrus21-common-2.1.16-6ubuntu0.1 (Ubuntu 4.10)
- cyrus21-dev-2.1.16-6ubuntu0.1 (Ubuntu 4.10)
- cyrus21-doc-2.1.16-6ubuntu0.1 (Ubuntu 4.10)
- cyrus21-imapd-2.1.16-6ubuntu0.1 (Ubuntu 4.10)
- cyrus21-murder-2.1.16-6ubuntu0.1 (Ubuntu 4.10)
- cyrus21-pop3d-2.1.16-6ubuntu0.1 (Ubuntu 4.10)
- libcyrus-imap-perl21-2.1.16-6ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20647);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "31-1");
script_summary(english:"cyrus21-imapd vulnerabilities");
script_name(english:"USN31-1 : cyrus21-imapd vulnerabilities");
script_cve_id("CVE-2004-1012","CVE-2004-1013");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cyrus21-admin", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cyrus21-admin-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cyrus21-admin-2.1.16-6ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cyrus21-clients", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cyrus21-clients-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cyrus21-clients-2.1.16-6ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cyrus21-common", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cyrus21-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cyrus21-common-2.1.16-6ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cyrus21-dev", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cyrus21-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cyrus21-dev-2.1.16-6ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cyrus21-doc", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cyrus21-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cyrus21-doc-2.1.16-6ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cyrus21-imapd", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cyrus21-imapd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cyrus21-imapd-2.1.16-6ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cyrus21-murder", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cyrus21-murder-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cyrus21-murder-2.1.16-6ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cyrus21-pop3d", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cyrus21-pop3d-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cyrus21-pop3d-2.1.16-6ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcyrus-imap-perl21", pkgver: "2.1.16-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcyrus-imap-perl21-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcyrus-imap-perl21-2.1.16-6ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
