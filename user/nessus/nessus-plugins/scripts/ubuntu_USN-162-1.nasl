# This script was automatically generated from the 162-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- ekg 
- libgadu-dev 
- libgadu3 


Description :

Marcin Owsiany and Wojtek Kaniewski discovered that some contributed
scripts (contrib/ekgh, contrib/ekgnv.sh, and contrib/getekg.sh) in the
ekg package created temporary files in an insecure way, which allowed
exploitation of a race condition to create or overwrite files with the
privileges of the user invoking the script. (CVE-2005-1850)

Marcin Owsiany and Wojtek Kaniewski discovered a shell command
injection vulnerability in a contributed utility
(contrib/scripts/ekgbot-pre1.py). By sending specially crafted content
to the bot, an attacker could exploit this to execute arbitrary code
with the privileges of the user running ekgbot. (CVE-2005-1851)

Marcin Ślusarz discovered an integer overflow in the Gadu library. By
sending a specially crafted incoming message, a remote attacker could
execute arbitrary code with the privileges of the application using
libgadu. (CVE-2005-1852)

Eric Romang discovered that another contributed script
(contrib/scripts/linki.py) created temporary files in an insecure way,
whi
[...]

Solution :

Upgrade to : 
- ekg-1.5-4ubuntu1.2 (Ubuntu 5.04)
- libgadu-dev-1.5-4ubuntu1.2 (Ubuntu 5.04)
- libgadu3-1.5-4ubuntu1.2 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20568);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "162-1");
script_summary(english:"ekg vulnerabilities");
script_name(english:"USN162-1 : ekg vulnerabilities");
script_cve_id("CVE-2005-1850","CVE-2005-1851","CVE-2005-1852","CVE-2005-1916","CVE-2005-2369","CVE-2005-2370","CVE-2005-2448");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "ekg", pkgver: "1.5-4ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package ekg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ekg-1.5-4ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libgadu-dev", pkgver: "1.5-4ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgadu-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libgadu-dev-1.5-4ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libgadu3", pkgver: "1.5-4ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libgadu3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libgadu3-1.5-4ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
