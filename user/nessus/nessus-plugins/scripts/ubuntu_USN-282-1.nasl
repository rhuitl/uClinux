# This script was automatically generated from the 282-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- nagios-common 
- nagios-mysql 
- nagios-pgsql 
- nagios-text 


Description :

The nagios CGI scripts did not sufficiently check the validity of the
HTTP Content-Length attribute. By sending a specially crafted HTTP
request with a negative Content-Length value to the Nagios server, a
remote attacker could exploit this to execute arbitrary code with web
server privileges.

Please note that the Apache 2 web server already checks for valid
Content-Length values, so installations using Apache 2 (the only web
server officially supported in Ubuntu) are not vulnerable to this
flaw.

Solution :

Upgrade to : 
- nagios-common-1.3-cvs.20050402-4ubuntu3.1 (Ubuntu 5.10)
- nagios-mysql-1.3-cvs.20050402-4ubuntu3.1 (Ubuntu 5.10)
- nagios-pgsql-1.3-cvs.20050402-4ubuntu3.1 (Ubuntu 5.10)
- nagios-text-1.3-cvs.20050402-4ubuntu3.1 (Ubuntu 5.10)



Risk factor : High
';

if (description) {
script_id(21376);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "282-1");
script_summary(english:"nagios vulnerability");
script_name(english:"USN282-1 : nagios vulnerability");
script_cve_id("CVE-2006-2162");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.10", pkgname: "nagios-common", pkgver: "1.3-cvs.20050402-4ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nagios-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nagios-common-1.3-cvs.20050402-4ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "nagios-mysql", pkgver: "1.3-cvs.20050402-4ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nagios-mysql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nagios-mysql-1.3-cvs.20050402-4ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "nagios-pgsql", pkgver: "1.3-cvs.20050402-4ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nagios-pgsql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nagios-pgsql-1.3-cvs.20050402-4ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "nagios-text", pkgver: "1.3-cvs.20050402-4ubuntu3.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package nagios-text-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nagios-text-1.3-cvs.20050402-4ubuntu3.1
');
}

if (w) { security_hole(port: 0, data: desc); }
