# This script was automatically generated from the 217-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "inkscape" is missing a security patch.

Description :

A buffer overflow has been discovered in the SVG importer of Inkscape.
By tricking an user into opening a specially crafted SVG image this
could be exploited to execute arbitrary code with the privileges of
the Inkscape user.

Solution :

Upgrade to : 
- inkscape-0.42-1build1ubuntu0.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20635);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "217-1");
script_summary(english:"inkscape vulnerability");
script_name(english:"USN217-1 : inkscape vulnerability");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "inkscape", pkgver: "0.42-1build1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package inkscape-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to inkscape-0.42-1build1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
