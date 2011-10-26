# This script was automatically generated from the dsa-1112
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several local vulnerabilities have been discovered in the MySQL database
server, which may lead to denial of service. The Common
Vulnerabilities and Exposures project identifies the following problems:
    "Kanatoko" discovered that the server can be crashed with feeding
    NULL values to the str_to_date() function.
    Jean-David Maillefer discovered that the server can be crashed with
    specially crafted date_format() function calls.
For the stable distribution (sarge) these problems have been fixed in
version 4.1.11a-4sarge5.
For the unstable distribution (sid) does no longer contain MySQL 4.1
packages. MySQL 5.0 from sid is not affected.
We recommend that you upgrade your mysql-dfsg-4.1 packages.


Solution : http://www.debian.org/security/2006/dsa-1112
Risk factor : High';

if (description) {
 script_id(22654);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1112");
 script_cve_id("CVE-2006-3081", "CVE-2006-3469");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1112] DSA-1112-1 mysql-dfsg-4.1");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1112-1 mysql-dfsg-4.1");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient14', release: '3.1', reference: '4.1.11a-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14 is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14_4.1.11a-4sarge5\n');
}
if (deb_check(prefix: 'libmysqlclient14-dev', release: '3.1', reference: '4.1.11a-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient14-dev is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient14-dev_4.1.11a-4sarge5\n');
}
if (deb_check(prefix: 'mysql-client-4.1', release: '3.1', reference: '4.1.11a-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-client-4.1_4.1.11a-4sarge5\n');
}
if (deb_check(prefix: 'mysql-common-4.1', release: '3.1', reference: '4.1.11a-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-common-4.1_4.1.11a-4sarge5\n');
}
if (deb_check(prefix: 'mysql-server-4.1', release: '3.1', reference: '4.1.11a-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server-4.1 is vulnerable in Debian 3.1.\nUpgrade to mysql-server-4.1_4.1.11a-4sarge5\n');
}
if (deb_check(prefix: 'mysql-dfsg-4.1', release: '3.1', reference: '4.1.11a-4sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-dfsg-4.1 is vulnerable in Debian sarge.\nUpgrade to mysql-dfsg-4.1_4.1.11a-4sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
