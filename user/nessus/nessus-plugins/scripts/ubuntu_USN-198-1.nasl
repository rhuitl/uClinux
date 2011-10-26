# This script was automatically generated from the 198-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- cfengine 
- cfengine-doc 


Description :

Javier Fernández-Sanguino Peña discovered that several tools in the
cfengine package (vicf, cfmailfilter, and cfcron) create and use
temporary files in an insecure way. A local attacker could exploit
this with a symlink attack to create or overwrite arbitrary files with
the privileges of the user running the cfengine program.

Solution :

Upgrade to : 
- cfengine-1.6.5-1ubuntu0.5.04.1 (Ubuntu 5.04)
- cfengine-doc-1.6.5-1ubuntu0.5.04.1 (Ubuntu 5.04)



Risk factor : High
';

if (description) {
script_id(20612);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "198-1");
script_summary(english:"cfengine vulnerabilities");
script_name(english:"USN198-1 : cfengine vulnerabilities");
script_cve_id("CVE-2005-2960","CVE-2005-3137");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "cfengine", pkgver: "1.6.5-1ubuntu0.5.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cfengine-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to cfengine-1.6.5-1ubuntu0.5.04.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "cfengine-doc", pkgver: "1.6.5-1ubuntu0.5.04.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package cfengine-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to cfengine-doc-1.6.5-1ubuntu0.5.04.1
');
}

if (w) { security_hole(port: 0, data: desc); }
