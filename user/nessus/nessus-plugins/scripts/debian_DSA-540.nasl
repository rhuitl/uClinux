# This script was automatically generated from the dsa-540
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jeroen van Wolffelaar discovered an insecure
temporary file vulnerability in the mysqlhotcopy script when using the
scp method which is part of the mysql-server package.
For the stable distribution (woody) this problem has been fixed in
version 3.23.49-8.7 of mysql.
For the unstable distribution (sid) this problem has been fixed in
version 4.0.20-11 of mysql-dfsg.
We recommend that you upgrade your mysql-server package.


Solution : http://www.debian.org/security/2004/dsa-540
Risk factor : High';

if (description) {
 script_id(15377);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "540");
 script_cve_id("CVE-2004-0457");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA540] DSA-540-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-540-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.7\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.7\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.7\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.7\n');
}
if (deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 3.0.\nUpgrade to mysql-doc_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.7\n');
}
if (deb_check(prefix: 'mysql', release: '3.1', reference: '4.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian 3.1.\nUpgrade to mysql_4.0\n');
}
if (deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian woody.\nUpgrade to mysql_3.23.49-8\n');
}
if (w) { security_hole(port: 0, data: desc); }
