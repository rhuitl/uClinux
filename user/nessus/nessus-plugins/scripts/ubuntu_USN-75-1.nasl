# This script was automatically generated from the 75-1 Ubuntu Security Notice
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

Recently it was discovered that cpio created world-writeable files
when used in -o/--create mode with giving an output file (with -O).
This allowed any user to modify the created cpio archives. Now cpio
respects the current umask setting of the user.

Note: This vulnerability has already been fixed in a very old version
of cpio, but the fix was never ported to the current version.
Therefore the CAN number was assigned to the year 1999.

Solution :

Upgrade to : 
- cpio-2.5-1.1ubuntu0.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20697);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "75-1");
script_summary(english:"cpio vulnerability");
script_name(english:"USN75-1 : cpio vulnerability");
script_cve_id("CVE-1999-1572");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "cpio", pkgver: "2.5-1.1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cpio-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to cpio-2.5-1.1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
