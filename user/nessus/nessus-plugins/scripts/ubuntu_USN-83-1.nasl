# This script was automatically generated from the 83-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- lesstif-bin 
- lesstif-dev 
- lesstif-doc 
- lesstif1 
- lesstif2 
- lesstif2-dev 


Description :

Several vulnerabilities have been found in the XPM image decoding
functions of the LessTif library. If an attacker tricked a user into
loading a malicious XPM image with an application that uses LessTif,
he could exploit this to execute arbitrary code in the context of the
user opening the image.

Ubuntu does not contain any server applications using LessTif, so
there is no possibility of privilege escalation.

Please note that this update only fixes lesstif2. The older lesstif1
version is also affected. A proper fix for lesstif1 will still take
some time and will be done in a separate USN. However, no Ubuntu
application uses lesstif1, so this could only affect you if you use
third party software which depends on this library.

Solution :

Upgrade to : 
- lesstif-bin-0.93.94-4ubuntu1.1 (Ubuntu 4.10)
- lesstif-dev-0.93.94-4ubuntu1.1 (Ubuntu 4.10)
- lesstif-doc-0.93.94-4ubuntu1.1 (Ubuntu 4.10)
- lesstif1-0.93.94-4ubuntu1.1 (Ubuntu 4.10)
- lesstif2-0.93.94-4ubuntu1.1 (Ubuntu 4.10)
- lesstif2-dev-0.93.94-4ubuntu1.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20707);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "83-1");
script_summary(english:"lesstif1-1 vulnerabilities");
script_name(english:"USN83-1 : lesstif1-1 vulnerabilities");
script_cve_id("CVE-2004-0914");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "lesstif-bin", pkgver: "0.93.94-4ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lesstif-bin-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif-bin-0.93.94-4ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif-dev", pkgver: "0.93.94-4ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lesstif-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif-dev-0.93.94-4ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif-doc", pkgver: "0.93.94-4ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lesstif-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif-doc-0.93.94-4ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif1", pkgver: "0.93.94-4ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lesstif1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif1-0.93.94-4ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif2", pkgver: "0.93.94-4ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lesstif2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif2-0.93.94-4ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "lesstif2-dev", pkgver: "0.93.94-4ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lesstif2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lesstif2-dev-0.93.94-4ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
