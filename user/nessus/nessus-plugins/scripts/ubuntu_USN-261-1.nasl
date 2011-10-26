# This script was automatically generated from the 261-1 Ubuntu Security Notice
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
- libapache2-mod-php5 
- php-pear 
- php4 
- php4-cgi 
- php4-cli 
- php4-common 
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
- php5 
- php5-cgi 
- php5-cli 
- php5-common 
- php5-curl 
- php5-dev 
- php5-gd 
- php5-ldap 
- php5-mhash 
- php5-mysql 
- php5-odbc 
- php5-pgsql 
- php5-recode 

[...]

Description :

Stefan Esser discovered that the \'session\' module did not sufficiently
verify the validity of the user-supplied session ID. A remote attacker
could exploit this to insert arbitrary HTTP headers into the response
sent by the PHP application, which could lead to HTTP Response
Splitting (forging of arbitrary responses on behalf the PHP
application) and Cross Site Scripting (XSS) (execution of arbitrary
web script code in the client\'s browser) attacks. (CVE-2006-0207)

PHP applications were also vulnerable to several Cross Site Scripting
(XSS) flaws if the options \'display_errors\' and \'html_errors\' were
enabled. Please note that enabling \'html_errors\' is not recommended
for production systems. (CVE-2006-0208)

Solution :

Upgrade to : 
- libapache2-mod-php4-4.3.10-10ubuntu4.4 (Ubuntu 5.04)
- libapache2-mod-php5-5.0.5-2ubuntu1.2 (Ubuntu 5.10)
- php-pear-5.0.5-2ubuntu1.2 (Ubuntu 5.10)
- php4-4.3.10-10ubuntu4.4 (Ubuntu 5.04)
- php4-cgi-4.3.10-10ubuntu4.4 (Ubuntu 5.04)
- php4-cli-4.3.10-10ubuntu4.4 (Ubuntu 5.04)
- php4-common-4.3.10-10ubuntu4.4 (Ubuntu 5.04)
- php4-curl-4.3.8-3ubuntu7.15 (Ubuntu 4.10)
- php4-dev-4.3.10-10ubuntu4.4 (Ubuntu 5.04)
- php4-domxml-4.3.8-3ubuntu7.15 (Ubuntu 4.10)
- php4-gd-4.3.8-3ubuntu7.15 (Ubuntu 4.
[...]


Risk factor : High
';

if (description) {
script_id(21068);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2005 Canonical, Inc. / NASL script (C) 2005 Michel Arboi <mikhail@nessus.org>");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
script_description(english: desc);

script_xref(name: "USN", value: "261-1");
script_summary(english:"php4, php5 vulnerabilities");
script_name(english:"USN261-1 : php4, php5 vulnerabilities");
script_cve_id("CVE-2006-0207","CVE-2006-0208");
exit(0);
}

include('ubuntu.inc');

found = ubuntu_check(osver: "5.04", pkgname: "libapache2-mod-php4", pkgver: "4.3.10-10ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapache2-mod-php4-4.3.10-10ubuntu4.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libapache2-mod-php5", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package libapache2-mod-php5-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libapache2-mod-php5-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php-pear", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php-pear-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php-pear-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4", pkgver: "4.3.10-10ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-4.3.10-10ubuntu4.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-cgi", pkgver: "4.3.10-10ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-cgi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-cgi-4.3.10-10ubuntu4.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-cli", pkgver: "4.3.10-10ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-cli-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-cli-4.3.10-10ubuntu4.4
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-common", pkgver: "4.3.10-10ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-common-4.3.10-10ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-curl", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-curl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-curl-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-dev", pkgver: "4.3.10-10ubuntu4.4");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-dev-4.3.10-10ubuntu4.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-domxml", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-domxml-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-domxml-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-gd", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-gd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-gd-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-ldap", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-ldap-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-ldap-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mcal", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mcal-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mcal-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mhash", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mhash-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mhash-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mysql", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-mysql-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mysql-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-odbc", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-odbc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-odbc-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-pear", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-pear-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-pear-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-recode", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-recode-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-recode-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-snmp", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-snmp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-snmp-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-sybase", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-sybase-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-sybase-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-xslt", pkgver: "4.3.8-3ubuntu7.15");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php4-xslt-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-xslt-4.3.8-3ubuntu7.15
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-cgi", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-cgi-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-cgi-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-cli", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-cli-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-cli-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-common", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-common-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-curl", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-curl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-curl-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-dev", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-dev-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-gd", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-gd-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-gd-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-ldap", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-ldap-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-ldap-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-mhash", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-mhash-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-mhash-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-mysql", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-mysql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-mysql-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-odbc", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-odbc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-odbc-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-pgsql", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-pgsql-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-pgsql-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-recode", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-recode-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-recode-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-snmp", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-snmp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-snmp-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-sqlite", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-sqlite-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-sqlite-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-sybase", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-sybase-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-sybase-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-xmlrpc", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-xmlrpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-xmlrpc-5.0.5-2ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "php5-xsl", pkgver: "5.0.5-2ubuntu1.2");
if (! isnull(found)) {
w++;
desc = strcat(desc, '
The package php5-xsl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to php5-xsl-5.0.5-2ubuntu1.2
');
}

if (w) { security_hole(port: 0, data: desc); }
