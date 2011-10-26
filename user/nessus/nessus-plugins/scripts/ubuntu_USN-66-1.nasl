# This script was automatically generated from the 66-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libapache2-mod-php4 
- php4 
- php4-cgi 
- php4-curl 
- php4-dev 
- php4-domxml 
- php4-gd 
- php4-ldap 
- php4-mcal 
- php4-mhash 
- php4-mysql 
- php4-odbc 
- php4-pear 
- php4-recode 
- php4-snmp 
- php4-sybase 
- php4-xslt 


Description :

FraMe from kernelpanik.org reported that the cURL module does not
respect open_basedir restrictions. As a result, scripts which used
cURL to open files with an user-specified path could read arbitrary
local files outside of the open_basedir directory.

Stefano Di Paola discovered a vulnerability in PHP\'s shmop_write()
function. Its "offset" parameter was not checked for negative values,
which allowed an attacker to write arbitrary data to arbitrary memory
locations. A script which passed unchecked parameters to
shmop_write() could possibly be exploited to execute arbitrary code
with the privileges of the web server and to bypass safe mode
restrictions.

Solution :

Upgrade to : 
- libapache2-mod-php4-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-cgi-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-curl-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-dev-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-domxml-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-gd-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-ldap-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-mcal-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-mhash-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-mysql-4.3.8-3ubuntu7.3 (Ubuntu 4.10)
- php4-odbc-4.3.8-3
[...]


Risk factor : High
';

if (description) {
script_id(20685);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "66-1");
script_summary(english:"php4 vulnerabilities");
script_name(english:"USN66-1 : php4 vulnerabilities");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "4.10", pkgname: "libapache2-mod-php4", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-php4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapache2-mod-php4-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-cgi", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-cgi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-cgi-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-curl", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-curl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-curl-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-dev", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-dev-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-domxml", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-domxml-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-domxml-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-gd", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-gd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-gd-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-ldap", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-ldap-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-ldap-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mcal", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mcal-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mcal-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mhash", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mhash-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mhash-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mysql", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mysql-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mysql-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-odbc", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-odbc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-odbc-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-pear", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-pear-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-pear-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-recode", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-recode-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-recode-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-snmp", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-snmp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-snmp-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-sybase", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-sybase-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-sybase-4.3.8-3ubuntu7.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-xslt", pkgver: "4.3.8-3ubuntu7.3");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-xslt-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-xslt-4.3.8-3ubuntu7.3
');
}

if (w) { security_hole(port: 0, data: desc); }
