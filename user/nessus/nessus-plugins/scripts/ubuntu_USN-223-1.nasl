# This script was automatically generated from the 223-1 Ubuntu Security Notice
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

Javier Fernández-Sanguino Peña discovered that Inkscape\'s ps2epsi.sh
script, which converts PostScript files to Encapsulated PostScript
format, creates a temporary file in an insecure way. A local attacker
could exploit this with a symlink attack to create or overwrite
arbitrary files with the privileges of the user running Inkscape.

Solution :

Upgrade to : 
- inkscape-0.40-2ubuntu1.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20766);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "223-1");
script_summary(english:"inkscape vulnerability");
script_name(english:"USN223-1 : inkscape vulnerability");
script_cve_id("CVE-2005-3885");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "inkscape", pkgver: "0.40-2ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package inkscape-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to inkscape-0.40-2ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
