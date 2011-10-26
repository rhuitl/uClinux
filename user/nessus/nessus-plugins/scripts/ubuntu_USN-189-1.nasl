# This script was automatically generated from the 189-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "cpio" is missing a security patch.

Description :

Imran Ghory found a race condition in the handling of output files.
While a file was unpacked with cpio, a local attacker with write
permissions to the target directory could exploit this to change the
permissions of arbitrary files of the cpio user. (CVE-2005-1111)

Imran Ghory discovered a path traversal vulnerability. Even when the
--no-absolute-filenames option was specified, cpio did not filter out
".." path components. By tricking an user into unpacking a malicious
cpio archive, this could be exploited to install files in arbitrary
paths with the privileges of the user calling cpio. (CVE-2005-1229)

Solution :

Upgrade to : 
- cpio-2.5-1.1ubuntu1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20601);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "189-1");
script_summary(english:"cpio vulnerabilities");
script_name(english:"USN189-1 : cpio vulnerabilities");
script_cve_id("CVE-2005-1111","CVE-2005-1229");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "cpio", pkgver: "2.5-1.1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cpio-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to cpio-2.5-1.1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
