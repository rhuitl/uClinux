# This script was automatically generated from the 78-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

The remote package "mailman" is missing a security patch.

Description :

An path traversal vulnerability has been discovered in the "private"
module of Mailman. A flawed path sanitation algorithm allowed the
construction of URLS to arbitrary files readable by Mailman. This
allowed a remote attacker to retrieve configuration and password
databases, private list archives, and other files.

Solution :

Upgrade to : 
- mailman-2.1.5-1ubuntu2.3 (Ubuntu 4.10)



Risk factor : High
';

if (description) {
script_id(20700);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "78-1");
script_summary(english:"mailman vulnerabilities");
script_name(english:"USN78-1 : mailman vulnerabilities");
script_cve_id("CVE-2005-0202");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "mailman", pkgver: "2.1.5-1ubuntu2.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package mailman-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mailman-2.1.5-1ubuntu2.3
');
}

if (w) { security_hole(port: 0, data: desc); }
