# This script was automatically generated from the 14-1 Ubuntu Security Notice
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
- libkpathsea-dev 
- libkpathsea3 
- tetex-bin 
- xpdf 
- xpdf-common 
- xpdf-reader 
- xpdf-utils 


Description :

Markus Meissner discovered even more integer overflow vulnerabilities
in xpdf, a viewer for PDF files. These integer overflows can
eventually lead to buffer overflows.

The Common UNIX Printing System (CUPS) uses the same code to print PDF
files; tetex-bin uses the code to generate PDF output and process
included PDF files. In any case, these vulnerabilities could be
exploited by an attacker providing a specially crafted PDF file which,
when processed by CUPS, xpdf, or pdflatex, could result in abnormal
program termination or the execution of program code supplied by the
attacker.

In the case of CUPS, this bug could be exploited to gain the privileges of
the CUPS print server (by default, user cupsys).

In the cases of xpdf and pdflatex, this bug could be exploited to gain
the privileges of the user invoking the program.

Solution :

Upgrade to : 
- cupsys-1.1.20final+cvs20040330-4ubuntu16.2 (Ubuntu 4.10)
- cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.2 (Ubuntu 4.10)
- cupsys-client-1.1.20final+cvs20040330-4ubuntu16.2 (Ubuntu 4.10)
- libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.2 (Ubuntu 4.10)
- libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.2 (Ubuntu 4.10)
- libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.2 (Ubuntu 4.10)
- libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.2 (Ubuntu 4.10)
- libkpathsea-dev-2.0.2-21ubuntu0.
[...]


Risk factor : High
';

if (description) {
script_id(20532);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "14-1");
script_summary(english:"xpdf vulnerabilities");
script_name(english:"USN14-1 : xpdf vulnerabilities");
script_cve_id("CVE-2004-0888","CVE-2004-0889");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cupsys", pkgver: "1.1.20final+cvs20040330-4ubuntu16.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-1.1.20final+cvs20040330-4ubuntu16.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-bsd", pkgver: "1.1.20final+cvs20040330-4ubuntu16.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-bsd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-client", pkgver: "1.1.20final+cvs20040330-4ubuntu16.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-client-1.1.20final+cvs20040330-4ubuntu16.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2", pkgver: "1.1.20final+cvs20040330-4ubuntu16.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-gnutls10", pkgver: "1.1.20final+cvs20040330-4ubuntu16.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-gnutls10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libkpathsea-dev", pkgver: "2.0.2-21ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkpathsea-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkpathsea-dev-2.0.2-21ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libkpathsea3", pkgver: "2.0.2-21ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libkpathsea3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkpathsea3-2.0.2-21ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "tetex-bin", pkgver: "2.0.2-21ubuntu0.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package tetex-bin-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to tetex-bin-2.0.2-21ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf", pkgver: "3.00-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-3.00-8ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-common", pkgver: "3.00-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-common-3.00-8ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-reader", pkgver: "3.00-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-reader-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-reader-3.00-8ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-utils", pkgver: "3.00-8ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package xpdf-utils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-utils-3.00-8ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
