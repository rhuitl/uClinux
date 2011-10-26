# This script was automatically generated from the 239-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "libapache2-mod-auth-pgsql" is missing a security patch.

Description :

Several format string vulnerabilities were discovered in the error
logging handling. By sending specially crafted user names, an
unauthenticated remote attacker could exploit this to crash the Apache
server or possibly even execute arbitrary code with the privileges of
Apache (user \'www-data\').

Solution :

Upgrade to : 
- libapache2-mod-auth-pgsql-2.0.2b1-6ubuntu0.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(20786);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "239-1");
script_summary(english:"libapache2-mod-auth-pgsql vulnerability");
script_name(english:"USN239-1 : libapache2-mod-auth-pgsql vulnerability");
script_cve_id("CVE-2005-3656");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "libapache2-mod-auth-pgsql", pkgver: "2.0.2b1-6ubuntu0.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-auth-pgsql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libapache2-mod-auth-pgsql-2.0.2b1-6ubuntu0.1
');
}

if (w) { security_hole(port: 0, data: desc); }
