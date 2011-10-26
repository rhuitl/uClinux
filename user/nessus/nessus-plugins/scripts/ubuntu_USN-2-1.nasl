# This script was automatically generated from the 2-1 Ubuntu Security Notice
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
- xpdf 
- xpdf-common 
- xpdf-reader 
- xpdf-utils 


Description :

Chris Evans discovered several integer overflow vulnerabilities in xpdf, a
viewer for PDF files.  The Common UNIX Printing System (CUPS) also uses the
same code to print PDF files.  In either case, these vulnerabilities could
be exploited by an attacker by providing a specially crafted PDF file which,
when processed by CUPS or xpdf, could result in abnormal program termination
or the execution of program code supplied by the attacker.

In the case of CUPS, this bug could be exploited to gain the privileges of
the CUPS print server (by default, user cupsys).

In the case of xpdf, this bug could be exploited to gain the privileges of
the user invoking xpdf.

Solution :

Upgrade to : 
- cupsys-1.1.20final+cvs20040330-4ubuntu16.1 (Ubuntu 4.10)
- cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.1 (Ubuntu 4.10)
- cupsys-client-1.1.20final+cvs20040330-4ubuntu16.1 (Ubuntu 4.10)
- libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.1 (Ubuntu 4.10)
- libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.1 (Ubuntu 4.10)
- libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.1 (Ubuntu 4.10)
- libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.1 (Ubuntu 4.10)
- xpdf-3.00-8ubuntu1.1 (Ubuntu 4.1
[...]


Risk factor : High
';

if (description) {
script_id(20614);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "2-1");
script_summary(english:"xpdf vulnerabilities");
script_name(english:"USN2-1 : xpdf vulnerabilities");
script_cve_id("CVE-2004-0889");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cupsys", pkgver: "1.1.20final+cvs20040330-4ubuntu16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-1.1.20final+cvs20040330-4ubuntu16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-bsd", pkgver: "1.1.20final+cvs20040330-4ubuntu16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-bsd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-client", pkgver: "1.1.20final+cvs20040330-4ubuntu16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-client-1.1.20final+cvs20040330-4ubuntu16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2", pkgver: "1.1.20final+cvs20040330-4ubuntu16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-gnutls10", pkgver: "1.1.20final+cvs20040330-4ubuntu16.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-gnutls10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf", pkgver: "3.00-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-3.00-8ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-common", pkgver: "3.00-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-common-3.00-8ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-reader", pkgver: "3.00-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-reader-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-reader-3.00-8ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-utils", pkgver: "3.00-8ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-utils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-utils-3.00-8ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
