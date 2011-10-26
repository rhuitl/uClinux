# This script was automatically generated from the 238-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "blender" is missing a security patch.

Description :

Damian Put discovered that Blender did not properly validate a
\'length\' value in .blend files. Negative values led to an
insufficiently sized memory allocation. By tricking a user into
opening a specially crafted .blend file, this could be exploited to
execute arbitrary code with the privileges of the Blender user.

Solution :

Upgrade to : 
- blender-2.37a-1ubuntu1.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20785);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "238-2");
script_summary(english:"blender vulnerability");
script_name(english:"USN238-2 : blender vulnerability");
script_cve_id("CVE-2005-4470");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "blender", pkgver: "2.37a-1ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package blender-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to blender-2.37a-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
