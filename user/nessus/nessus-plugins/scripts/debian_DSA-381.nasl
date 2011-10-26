# This script was automatically generated from the dsa-381
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
MySQL, a popular relational database system, contains a buffer
overflow condition which could be exploited by a user who has
permission to execute "ALTER TABLE" commands on the tables in the
"mysql" database.  If successfully exploited, this vulnerability
could allow the attacker to execute arbitrary code with the
privileges of the mysqld process (by default, user "mysql").  Since
the "mysql" database is used for MySQL\'s internal record keeping, by
default the mysql administrator "root" is the only user with
permission to alter its tables.
For the stable distribution (woody) this problem has been fixed in
version 3.23.49-8.5.
For the unstable distribution (sid) this problem will be fixed soon.
Refer to Debian bug #210403.
We recommend that you update your mysql package.


Solution : http://www.debian.org/security/2003/dsa-381
Risk factor : High';

if (description) {
 script_id(15218);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "381");
 script_cve_id("CVE-2003-0780");
 script_bugtraq_id(8590);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA381] DSA-381-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-381-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.5\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 3.0.\nUpgrade to mysql-doc_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian woody.\nUpgrade to mysql_3.23.49-8.5\n');
}
if (w) { security_hole(port: 0, data: desc); }
