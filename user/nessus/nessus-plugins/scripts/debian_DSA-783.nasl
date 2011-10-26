# This script was automatically generated from the dsa-783
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Eric Romang discovered a temporary file vulnerability in a script
accompanied with MySQL, a popular database, that allows an attacker to
execute arbitrary SQL commands when the server is installed or
updated.
The old stable distribution (woody) as well as mysql-dfsg are not
affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 4.1.11a-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 4.1.12 for mysql-dfsg-4.1 and 5.0.11beta-3 of mysql-dfsg-5.0.
We recommend that you upgrade your mysql packages.


Solution : http://www.debian.org/security/2005/dsa-783
Risk factor : High';

if (description) {
 script_id(19526);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "783");
 script_cve_id("CVE-2005-1636");
 script_bugtraq_id(13660);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA783] DSA-783-1 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-783-1 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mysql-dfsg-4.1', release: '', reference: '4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-dfsg-4.1 is vulnerable in Debian .\nUpgrade to mysql-dfsg-4.1_4.1\n');
}
if (deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14 is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14_4.1.11a-4sarge1\n');
}
if (deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14-dev is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14-dev_4.1.11a-4sarge1\n');
}
if (deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-client-4.1_4.1.11a-4sarge1\n');
}
if (deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-common-4.1_4.1.11a-4sarge1\n');
}
if (deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-server-4.1_4.1.11a-4sarge1\n');
}
if (deb_check(prefix: 'mysql-dfsg-4.1', release: '3.1', reference: '4.1.11a-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-dfsg-4.1 is vulnerable in Debian sarge.\nUpgrade to mysql-dfsg-4.1_4.1.11a-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
