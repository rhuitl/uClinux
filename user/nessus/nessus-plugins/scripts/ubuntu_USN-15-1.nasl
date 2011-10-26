# This script was automatically generated from the 15-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "lvm10" is missing a security patch.

Description :

Recently, Trustix Secure Linux discovered a vulnerability in a
supplemental script of the lvm10 package. The program
"lvmcreate_initrd" created a temporary directory in an insecure way,
which could allow a symlink attack to create or overwrite arbitrary
files with the privileges of the user invoking the program.

Solution :

Upgrade to : 
- lvm10-1.0.8-4ubuntu1.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20547);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "15-1");
script_summary(english:"lvm10 vulnerability");
script_name(english:"USN15-1 : lvm10 vulnerability");
script_cve_id("CVE-2004-0972");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "lvm10", pkgver: "1.0.8-4ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package lvm10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to lvm10-1.0.8-4ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
