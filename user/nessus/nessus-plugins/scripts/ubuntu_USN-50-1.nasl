# This script was automatically generated from the 50-1 Ubuntu Security Notice
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

CVE-2004-1125:

  The recent USN-48-1 fixed a buffer overflow in xpdf. Since CUPS
  contains xpdf code to convert incoming PDF files to the PostScript
  format, this vulnerability applies to cups as well.

  In this case it could even lead to privilege escalation: if an
  attacker submitted a malicious PDF file for printing, he could be
  able to execute arbitrary commands with the privileges of the
  CUPS server.

  Please note that the Ubuntu version of CUPS runs as a minimally
  privileged user \'cupsys\' by default, so there is no possibility of
  root privilege escalation. The privileges of the \'cupsys\' user are
  confined to modifying printer configurations, altering print jobs,
  and controlling printers.

CVE-2004-1267:

  Ariel Berkman discovered a buffer overflow in the ParseCommand()
  function of the HPGL input driver. If an attacker printed a
  malicious HPGL file, they could exploit this to execute arbitrary
  commands with the privileges of the CUPS server.

CVE-2004-1268, CVE-2004-1269, CAN
[...]

Solution :

Upgrade to : 
- cupsys-1.1.20final+cvs20040330-4ubuntu16.3 (Ubuntu 4.10)
- cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.3 (Ubuntu 4.10)
- cupsys-client-1.1.20final+cvs20040330-4ubuntu16.3 (Ubuntu 4.10)
- libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.3 (Ubuntu 4.10)
- libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.3 (Ubuntu 4.10)
- libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.3 (Ubuntu 4.10)
- libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.3 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20668);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "50-1");
script_summary(english:"cupsys vulnerabilities");
script_name(english:"USN50-1 : cupsys vulnerabilities");
script_cve_id("CVE-2004-1125","CVE-2004-1267","CVE-2004-1268","CVE-2004-1269","CVE-2004-1270","CVE-2004-2467");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cupsys", pkgver: "1.1.20final+cvs20040330-4ubuntu16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-1.1.20final+cvs20040330-4ubuntu16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-bsd", pkgver: "1.1.20final+cvs20040330-4ubuntu16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-bsd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-bsd-1.1.20final+cvs20040330-4ubuntu16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "cupsys-client", pkgver: "1.1.20final+cvs20040330-4ubuntu16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cupsys-client-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cupsys-client-1.1.20final+cvs20040330-4ubuntu16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2", pkgver: "1.1.20final+cvs20040330-4ubuntu16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-1.1.20final+cvs20040330-4ubuntu16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsimage2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsimage2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsimage2-dev-1.1.20final+cvs20040330-4ubuntu16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-dev", pkgver: "1.1.20final+cvs20040330-4ubuntu16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-dev-1.1.20final+cvs20040330-4ubuntu16.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libcupsys2-gnutls10", pkgver: "1.1.20final+cvs20040330-4ubuntu16.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libcupsys2-gnutls10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libcupsys2-gnutls10-1.1.20final+cvs20040330-4ubuntu16.3
');
}

if (w) { security_hole(port: 0, data: desc); }
