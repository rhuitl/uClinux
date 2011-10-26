# This script was automatically generated from the dsa-647
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernandez-Sanguino Peña from the Debian Security Audit Project
discovered a temporary file vulnerability in the mysqlaccess script of
MySQL that could allow an unprivileged user to let root overwrite
arbitrary files via a symlink attack and could also could unveil the
contents of a temporary file which might contain sensitive
information.
For the stable distribution (woody) this problem has been fixed in
version 3.23.49-8.9.
For the unstable distribution (sid) this problem has been fixed in
version 4.0.23-3 of mysql-dfsg and in version 4.1.8a-6 of
mysql-dfsg-4.1.
We recommend that you upgrade your mysql packages.


Solution : http://www.debian.org/security/2005/dsa-647
Risk factor : High';

if (description) {
 script_id(16214);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "647");
 script_cve_id("CVE-2005-0004");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA647] DSA-647-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-647-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.9\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.9\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.9\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.9\n');
}
if (deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 3.0.\nUpgrade to mysql-doc_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.9\n');
}
if (deb_check(prefix: 'mysql', release: '3.1', reference: '4.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian 3.1.\nUpgrade to mysql_4.0\n');
}
if (deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian woody.\nUpgrade to mysql_3.23.49-8.9\n');
}
if (w) { security_hole(port: 0, data: desc); }
