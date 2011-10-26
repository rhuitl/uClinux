# This script was automatically generated from the dsa-1092
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Josh Berkus and Tom Lane discovered that MySQL 4.1, a popular SQL
database, incorrectly parses a string escaped with mysql_real_escape()
which could lead to SQL injection.  This problem does only exist in
versions 4.1 and 5.0.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.1.11a-4sarge4.
For the unstable distribution (sid) this problem has been fixed in
version 5.0.21-4.
Version 4.0 in the stable distribution (sarge) is also not affected by
this problem.
We recommend that you upgrade your mysql packages.


Solution : http://www.debian.org/security/2006/dsa-1092
Risk factor : High';

if (description) {
 script_id(22634);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1092");
 script_cve_id("CVE-2006-2753");
 script_bugtraq_id(18219);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1092] DSA-1092-1 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1092-1 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mysql-dfsg-4.1', release: '', reference: '5.0.21-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-dfsg-4.1 is vulnerable in Debian .\nUpgrade to mysql-dfsg-4.1_5.0.21-4\n');
}
if (deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14 is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14_4.1.11a-4sarge4\n');
}
if (deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14-dev is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14-dev_4.1.11a-4sarge4\n');
}
if (deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-client-4.1_4.1.11a-4sarge4\n');
}
if (deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-common-4.1_4.1.11a-4sarge4\n');
}
if (deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-server-4.1_4.1.11a-4sarge4\n');
}
if (deb_check(prefix: 'mysql-dfsg-4.1', release: '3.1', reference: '4.1.11a-4sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-dfsg-4.1 is vulnerable in Debian sarge.\nUpgrade to mysql-dfsg-4.1_4.1.11a-4sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
