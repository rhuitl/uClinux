# This script was automatically generated from the 233-1 Ubuntu Security Notice
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

Steve Fosdick discovered a remote Denial of Service vulnerability in
fetchmail. When using fetchmail in \'multidrop\' mode, a malicious email
server could cause a crash by sending an email without any headers.
Since fetchmail is commonly called automatically (with cron, for
example), this crash could go unnoticed.

Solution :

Upgrade to : 
- fetchmail-6.2.5-13ubuntu3.2 (Ubuntu 5.10)
- fetchmail-ssl-6.2.5-13ubuntu3.2 (Ubuntu 5.10)
- fetchmailconf-6.2.5-13ubuntu3.2 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20777);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "233-1");
script_summary(english:"fetchmail vulnerability");
script_name(english:"USN233-1 : fetchmail vulnerability");
script_cve_id("CVE-2005-4348");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "fetchmail", pkgver: "6.2.5-13ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fetchmail-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to fetchmail-6.2.5-13ubuntu3.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "fetchmail-ssl", pkgver: "6.2.5-13ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fetchmail-ssl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to fetchmail-ssl-6.2.5-13ubuntu3.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "fetchmailconf", pkgver: "6.2.5-13ubuntu3.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package fetchmailconf-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to fetchmailconf-6.2.5-13ubuntu3.2
');
}

if (w) { security_hole(port: 0, data: desc); }
