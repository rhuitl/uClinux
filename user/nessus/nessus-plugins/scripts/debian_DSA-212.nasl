# This script was automatically generated from the dsa-212
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
While performing an audit of MySQL e-matters found several problems:
For Debian GNU/Linux 3.0/woody this has been fixed in version 3.23.49-8.2
and version 3.22.32-6.3 for Debian GNU/Linux 2.2/potato.
We recommend that you upgrade your mysql packages as soon as possible.


Solution : http://www.debian.org/security/2002/dsa-212
Risk factor : High';

if (description) {
 script_id(15049);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "212");
 script_cve_id("CVE-2002-1376", "CVE-2002-1373", "CVE-2002-1374", "CVE-2002-1375");
 script_bugtraq_id(6368, 6373, 6375);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA212] DSA-212-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-212-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mysql-client', release: '2.2', reference: '3.22.32-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 2.2.\nUpgrade to mysql-client_3.22.32-6.3\n');
}
if (deb_check(prefix: 'mysql-doc', release: '2.2', reference: '3.22.32-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 2.2.\nUpgrade to mysql-doc_3.22.32-6.3\n');
}
if (deb_check(prefix: 'mysql-server', release: '2.2', reference: '3.22.32-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 2.2.\nUpgrade to mysql-server_3.22.32-6.3\n');
}
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.2\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.2\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.2\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.2\n');
}
if (deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 3.0.\nUpgrade to mysql-doc_3.23.49-8.2\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
