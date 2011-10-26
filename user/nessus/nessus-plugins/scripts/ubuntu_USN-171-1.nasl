# This script was automatically generated from the 171-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Michel Arboi
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
desc = '
Synopsis :

These remote packages are missing security patches :
- libapache-mod-php4 
- libapache2-mod-php4 
- php4 
- php4-cgi 
- php4-cli 
- php4-common 
- php4-curl 
- php4-dev 
- php4-domxml 
- php4-gd 
- php4-imap 
- php4-ldap 
- php4-mcal 
- php4-mhash 
- php4-mysql 
- php4-odbc 
- php4-pear 
- php4-recode 
- php4-snmp 
- php4-sybase 
- php4-universe-common 
- php4-xslt 


Description :

CVE-2005-1751:

  The php4-dev package ships a copy of the "shtool" utility in
  /usr/lib/php4/build/, which provides useful functionality for
  developers of software packages.  Eric Romang discovered that shtool
  created temporary files in an insecure manner. This could allow
  a symlink attack to create or overwrite arbitrary files with the
  privileges of the user invoking the shtool program.

CVE-1005-1759:

  The creation of temporary files in shtool was also vulnerable to a
  race condition which allowed a local user to read the contents of the
  temporary file. However, this file does not usually contain sensitive
  information since shtool is usually used for building software
  packages.

CVE-2005-2498:

  Stefan Esser discovered another remote code execution vulnerability in
  the XMLRPC module of the PEAR (PHP Extension and Application
  Repository) extension of PHP. By sending specially crafted XMLRPC
  requests to an affected web server, a remote attacker could exploit
  this to execute arbitr
[...]

Solution :

Upgrade to : 
- libapache-mod-php4-4.3.10-10ubuntu3.4 (Ubuntu 5.04)
- libapache2-mod-php4-4.3.10-10ubuntu4.1 (Ubuntu 5.04)
- php4-4.3.10-10ubuntu4.1 (Ubuntu 5.04)
- php4-cgi-4.3.10-10ubuntu4.1 (Ubuntu 5.04)
- php4-cli-4.3.10-10ubuntu4.1 (Ubuntu 5.04)
- php4-common-4.3.10-10ubuntu4.1 (Ubuntu 5.04)
- php4-curl-4.3.10-10ubuntu3.4 (Ubuntu 5.04)
- php4-dev-4.3.10-10ubuntu4.1 (Ubuntu 5.04)
- php4-domxml-4.3.10-10ubuntu3.4 (Ubuntu 5.04)
- php4-gd-4.3.10-10ubuntu3.4 (Ubuntu 5.04)
- php4-imap-4.3.10-10ubuntu3.4 (Ub
[...]


Risk factor : High
';

if (description) {
script_id(20578);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "171-1");
script_summary(english:"php4 vulnerabilities");
script_name(english:"USN171-1 : php4 vulnerabilities");
script_cve_id("CVE-1005-1759","CVE-2005-1751","CVE-2005-1759","CVE-2005-2498");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libapache-mod-php4", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache-mod-php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapache-mod-php4-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libapache2-mod-php4", pkgver: "4.3.10-10ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapache2-mod-php4-4.3.10-10ubuntu4.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4", pkgver: "4.3.10-10ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-4.3.10-10ubuntu4.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-cgi", pkgver: "4.3.10-10ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-cgi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-cgi-4.3.10-10ubuntu4.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-cli", pkgver: "4.3.10-10ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-cli-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-cli-4.3.10-10ubuntu4.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-common", pkgver: "4.3.10-10ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-common-4.3.10-10ubuntu4.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-curl", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-curl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-curl-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-dev", pkgver: "4.3.10-10ubuntu4.1");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-dev-4.3.10-10ubuntu4.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-domxml", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-domxml-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-domxml-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-gd", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-gd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-gd-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-imap", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-imap-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-imap-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-ldap", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-ldap-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-ldap-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-mcal", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mcal-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-mcal-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-mhash", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mhash-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-mhash-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-mysql", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mysql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-mysql-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-odbc", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-odbc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-odbc-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-pear", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-pear-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-pear-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-recode", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-recode-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-recode-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-snmp", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-snmp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-snmp-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-sybase", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-sybase-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-sybase-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-universe-common", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-universe-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-universe-common-4.3.10-10ubuntu3.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-xslt", pkgver: "4.3.10-10ubuntu3.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-xslt-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-xslt-4.3.10-10ubuntu3.4
');
}

if (w) { security_hole(port: 0, data: desc); }
