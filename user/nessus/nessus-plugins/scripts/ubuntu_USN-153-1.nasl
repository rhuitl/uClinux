# This script was automatically generated from the 153-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- fetchmail 
- fetchmail-ssl 
- fetchmailconf 


Description :

Ross Boylan discovered a remote buffer overflow in fetchmail. By
sending invalid responses with very long UIDs, a faulty or malicious
POP server could crash fetchmail or execute arbitrary code with the
privileges of the user invoking fetchmail.

fetchmail is commonly run as root to fetch mail for multiple user
accounts; in this case, this vulnerability could be exploited to
compromise the whole system.

Solution :

Upgrade to : 
- fetchmail-6.2.5-12ubuntu1.1 (Ubuntu 5.04)
- fetchmail-ssl-6.2.5-12ubuntu1.1 (Ubuntu 5.04)
- fetchmailconf-6.2.5-12ubuntu1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20554);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "153-1");
script_summary(english:"fetchmail vulnerability");
script_name(english:"USN153-1 : fetchmail vulnerability");
script_cve_id("CVE-2005-2335");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "fetchmail", pkgver: "6.2.5-12ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fetchmail-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to fetchmail-6.2.5-12ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "fetchmail-ssl", pkgver: "6.2.5-12ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fetchmail-ssl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to fetchmail-ssl-6.2.5-12ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "fetchmailconf", pkgver: "6.2.5-12ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fetchmailconf-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to fetchmailconf-6.2.5-12ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
