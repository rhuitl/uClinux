# This script was automatically generated from the 257-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "tar" is missing a security patch.

Description :

Jim Meyering discovered that tar did not properly verify the validity
of certain header fields in a GNU tar archive. By tricking an user
into processing a specially crafted tar archive, this could be
exploited to execute arbitrary code with the privileges of the user.

The tar version in Ubuntu 4.10 is not affected by this vulnerability.

Solution :

Upgrade to : 
- tar-1.15.1-2ubuntu0.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21065);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "257-1");
script_summary(english:"tar vulnerability");
script_name(english:"USN257-1 : tar vulnerability");
script_cve_id("CVE-2006-0300");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "tar", pkgver: "1.15.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package tar-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to tar-1.15.1-2ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
