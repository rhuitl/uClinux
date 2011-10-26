# This script was automatically generated from the 3-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "gs-common" is missing a security patch.

Description :

Recently, Trustix Secure Linux discovered some vulnerabilities in the
gs-common package. The utilities "pv.sh" and "ps2epsi" created
temporary files in an insecure way, which allowed a symlink attack to
create or overwrite arbitrary files with the privileges of the user
invoking the program.

Solution :

Upgrade to : 
- gs-common-0.3.6ubuntu1.1 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20645);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "3-1");
script_summary(english:"GhostScript utility script vulnerabilities");
script_name(english:"USN3-1 : GhostScript utility script vulnerabilities");
script_cve_id("CVE-2004-0967");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "gs-common", pkgver: "0.3.6ubuntu1.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package gs-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to gs-common-0.3.6ubuntu1.1
');
}

if (w) { security_hole(port: 0, data: desc); }
