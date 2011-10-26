# This script was automatically generated from the dsa-303
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
CVE-2003-0073: The mysql package contains a bug whereby dynamically
allocated memory is freed more than once, which could be deliberately
triggered by an attacker to cause a crash, resulting in a denial of
service condition.  In order to exploit this vulnerability, a valid
username and password combination for access to the MySQL server is
required.
CVE-2003-0150: The mysql package contains a bug whereby a malicious
user, granted certain permissions within mysql, could create a
configuration file which would cause the mysql server to run as root,
or any other user, rather than the mysql user.
For the stable distribution (woody) both problems have been fixed in
version 3.23.49-8.4.
The old stable distribution (potato) is only affected by
CVE-2003-0150, and this has been fixed in version 3.22.32-6.4.
For the unstable distribution (sid), CVE-2003-0073 was fixed in
version 4.0.12-2, and CVE-2003-0150 will be fixed soon.
We recommend that you update your mysql package.


Solution : http://www.debian.org/security/2003/dsa-303
Risk factor : High';

if (description) {
 script_id(15140);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "303");
 script_cve_id("CVE-2003-0073", "CVE-2003-0150");
 script_bugtraq_id(7052);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA303] DSA-303-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-303-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mysql-client', release: '2.2', reference: '3.22.32-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 2.2.\nUpgrade to mysql-client_3.22.32-6.4\n');
}
if (deb_check(prefix: 'mysql-doc', release: '2.2', reference: '3.22.32-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 2.2.\nUpgrade to mysql-doc_3.22.32-6.4\n');
}
if (deb_check(prefix: 'mysql-server', release: '2.2', reference: '3.22.32-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 2.2.\nUpgrade to mysql-server_3.22.32-6.4\n');
}
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.4\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.4\n');
}
if (deb_check(prefix: 'mysql', release: '3.0', reference: '4.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian 3.0.\nUpgrade to mysql_4.0\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.4\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.4\n');
}
if (deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 3.0.\nUpgrade to mysql-doc_3.23.49-8.4\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.4\n');
}
if (deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian woody.\nUpgrade to mysql_3.23.49-8.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
