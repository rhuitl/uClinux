# This script was automatically generated from the 208-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- graphviz 
- graphviz-dev 
- graphviz-doc 


Description :

Javier Fernández-Sanguino Peña discovered that the "dotty" tool
created and used temporary files in an insecure way. A local attacker
could exploit this with a symlink attack to create or overwrite
arbitrary files with the privileges of the user running dotty.

Solution :

Upgrade to : 
- graphviz-2.2-1ubuntu0.1 (Ubuntu 5.04)
- graphviz-dev-2.2-1ubuntu0.1 (Ubuntu 5.04)
- graphviz-doc-2.2-1ubuntu0.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20625);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "208-1");
script_summary(english:"graphviz vulnerability");
script_name(english:"USN208-1 : graphviz vulnerability");
script_cve_id("CVE-2005-2965");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "graphviz", pkgver: "2.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package graphviz-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to graphviz-2.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "graphviz-dev", pkgver: "2.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package graphviz-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to graphviz-dev-2.2-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "graphviz-doc", pkgver: "2.2-1ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package graphviz-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to graphviz-doc-2.2-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
