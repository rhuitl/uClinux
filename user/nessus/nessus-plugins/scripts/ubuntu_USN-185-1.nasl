# This script was automatically generated from the 185-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- cupsys 
- cupsys-bsd 
- cupsys-client 
- libcupsimage2 
- libcupsimage2-dev 
- libcupsys2-dev 
- libcupsys2-gnutls10 


Description :

A flaw was detected in the printer access control list checking in the
CUPS server. Printer names were compared in a case sensitive manner;
by modifying the capitalization of printer names, a remote attacker
could circumvent ACLs and print to printers he should not have access
to.

The Ubuntu 5.04 version of cupsys is not vulnerable against this.

Solution :

Upgrade to : 
- cupsys-1.1.20final+cvs20040330-4ubuntu16.5 (Ubuntu 4.10)
- cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.5 (Ubuntu 4.10)
- cupsys-client-1.1.20final+cvs20040330-4ubuntu16.5 (Ubuntu 4.10)
- libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.5 (Ubuntu 4.10)
- libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.5 (Ubuntu 4.10)
- libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.5 (Ubuntu 4.10)
- libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.5 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20596);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "185-1");
script_summary(english:"cupsys vulnerability");
script_name(english:"USN185-1 : cupsys vulnerability");
script_cve_id("CVE-2004-2154");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cupsys", pkgver: "1.1.20final+cvs20040330-4ubuntu16.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-1.1.20final+cvs20040330-4ubuntu16.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-bsd", pkgver: "1.1.20final+cvs20040330-4ubuntu16.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-bsd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-client", pkgver: "1.1.20final+cvs20040330-4ubuntu16.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-client-1.1.20final+cvs20040330-4ubuntu16.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2", pkgver: "1.1.20final+cvs20040330-4ubuntu16.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.5
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-gnutls10", pkgver: "1.1.20final+cvs20040330-4ubuntu16.5");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-gnutls10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.5
');
}

if (w) { security_hole(port: 0, data: desc); }
