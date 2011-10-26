# This script was automatically generated from the dsa-1169
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several local vulnerabilities have been discovered in the MySQL
database server.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Michal Prokopiuk discovered that remote authenticated users are
    permitted to create and access a database if the lowercase
    spelling is the same as one they have been granted access to.
    Beat Vontobel discovered that certain queries replicated to a
    slave could crash the client and thus terminate the replication.
For the stable distribution (sarge) these problems have been fixed in
version 4.1.11a-4sarge7.  Version 4.0 is not affected by these
problems.
For the unstable distribution (sid) these problems have been fixed in
version 5.0.24-3.  The replication problem only exists in version 4.1.
We recommend that you upgrade your mysql-server-4.1 package.


Solution : http://www.debian.org/security/2006/dsa-1169
Risk factor : High';

if (description) {
 script_id(22711);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1169");
 script_cve_id("CVE-2006-4226", "CVE-2006-4380");
 script_bugtraq_id(19559);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1169] DSA-1169-1 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1169-1 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mysql-dfsg-4.1', release: '', reference: '5.0.24-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-dfsg-4.1 is vulnerable in Debian .\nUpgrade to mysql-dfsg-4.1_5.0.24-3\n');
}
if (deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14 is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14_4.1.11a-4sarge7\n');
}
if (deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14-dev is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14-dev_4.1.11a-4sarge7\n');
}
if (deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-client-4.1_4.1.11a-4sarge7\n');
}
if (deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-common-4.1_4.1.11a-4sarge7\n');
}
if (deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-server-4.1_4.1.11a-4sarge7\n');
}
if (deb_check(prefix: 'mysql-dfsg-4.1', release: '3.1', reference: '4.1.11a-4sarge7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-dfsg-4.1 is vulnerable in Debian sarge.\nUpgrade to mysql-dfsg-4.1_4.1.11a-4sarge7\n');
}
if (w) { security_hole(port: 0, data: desc); }
