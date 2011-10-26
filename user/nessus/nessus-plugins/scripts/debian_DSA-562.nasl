# This script was automatically generated from the dsa-562
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in MySQL, a commonly used SQL
database on Unix servers.  The following problems have been identified
by the Common Vulnerabilities and Exposures Project:
    Oleksandr Byelkin noticed that ALTER TABLE ... RENAME checks
    CREATE/INSERT rights of the old table instead of the new one.
    Lukasz Wojtow noticed a buffer overrun in the mysql_real_connect
    function.
    Dean Ellis noticed that multiple threads ALTERing the same (or
    different) MERGE tables to change the UNION can cause the server
    to crash or stall.
For the stable distribution (woody) these problems have been fixed in
version 3.23.49-8.8.
For the unstable distribution (sid) these problems have been fixed in
version 4.0.21-1.
We recommend that you upgrade your mysql and related packages and
restart services linking against them (e.g. Apache/PHP).


Solution : http://www.debian.org/security/2004/dsa-562
Risk factor : High';

if (description) {
 script_id(15660);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "562");
 script_cve_id("CVE-2004-0835", "CVE-2004-0836", "CVE-2004-0837");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA562] DSA-562-1 mysql");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-562-1 mysql");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient10', release: '3.0', reference: '3.23.49-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10 is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10_3.23.49-8.8\n');
}
if (deb_check(prefix: 'libmysqlclient10-dev', release: '3.0', reference: '3.23.49-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient10-dev is vulnerable in Debian 3.0.\nUpgrade to libmysqlclient10-dev_3.23.49-8.8\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.0', reference: '3.23.49-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.0.\nUpgrade to mysql-client_3.23.49-8.8\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.0', reference: '3.23.49-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.0.\nUpgrade to mysql-common_3.23.49-8.8\n');
}
if (deb_check(prefix: 'mysql-doc', release: '3.0', reference: '3.23.49-8.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-doc is vulnerable in Debian 3.0.\nUpgrade to mysql-doc_3.23.49-8.5\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.0', reference: '3.23.49-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.0.\nUpgrade to mysql-server_3.23.49-8.8\n');
}
if (deb_check(prefix: 'mysql', release: '3.1', reference: '4.0.21-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian 3.1.\nUpgrade to mysql_4.0.21-1\n');
}
if (deb_check(prefix: 'mysql', release: '3.0', reference: '3.23.49-8.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql is vulnerable in Debian woody.\nUpgrade to mysql_3.23.49-8.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
