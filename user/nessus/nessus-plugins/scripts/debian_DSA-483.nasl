# This script was automatically generated from the dsa-483
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in mysql, a common database
system.  Two scripts contained in the package don\'t create temporary
files in a secure fashion.  This could allow a local attacker to
overwrite files with the privileges of the user invoking the MySQL
server, which is often the root user.  The Common Vulnerabilities and
Exposures identifies the following problems:
    The script mysqlbug in MySQL allows local users to overwrite
    arbitrary files via a symlink attack.
    The script mysqld_multi in MySQL allows local users to overwrite
    arbitrary files via a symlink attack.
For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.6.
For the unstable distribution (sid) these problems will be fixed in
version 4.0.18-6 of mysql-dfsg.
We recommend that you upgrade your mysql, mysql-dfsg and related
packages.


Solution : http://www.debian.org/security/2004/dsa-483
Risk factor : High';

if (description) {
 script_id(15320);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "483");
 script_cve_id("CVE-2004-0381", "CVE-2004-0388");
 script_bugtraq_id(10142, 9976);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA483] DSA-483-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-483-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.6\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.6\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.6\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.6\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.6\n');
}
if (deb_check(prefix: 'mysql', release: '3.1', reference: '4.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian 3.1.\nUpgrade to mysql_4.0\n');
}
if (deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian woody.\nUpgrade to mysql_3.23.49-8.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
