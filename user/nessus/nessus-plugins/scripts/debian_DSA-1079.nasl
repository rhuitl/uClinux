# This script was automatically generated from the dsa-1079
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in MySQL, a popular SQL
database.  The Common Vulnerabilities and Exposures Project identifies
the following problems:
    Improper handling of SQL queries containing the NULL character
    allows local users to bypass logging mechanisms.
    Usernames without a trailing null byte allow remote attackers to
    read portions of memory.
    A request with an incorrect packet length allows remote attackers
    to obtain sensitive information.
    Specially crafted request packets with invalid length values allow
    the execution of arbitrary code.
The following vulnerability matrix shows which version of MySQL in
which distribution has this problem fixed:
We recommend that you upgrade your mysql packages.


Solution : http://www.debian.org/security/2006/dsa-1079
Risk factor : High';

if (description) {
 script_id(22621);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1079");
 script_cve_id("CVE-2006-0903", "CVE-2006-1516", "CVE-2006-1517", "CVE-2006-1518");
 script_bugtraq_id(16850, 17780);
 script_xref(name: "CERT", value: "602457");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1079] DSA-1079-1 mysql-dfsg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1079-1 mysql-dfsg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libmysqlclient12', release: '3.1', reference: '4.0.24-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient12 is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient12_4.0.24-10sarge2\n');
}
if (deb_check(prefix: 'libmysqlclient12-dev', release: '3.1', reference: '4.0.24-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmysqlclient12-dev is vulnerable in Debian 3.1.\nUpgrade to libmysqlclient12-dev_4.0.24-10sarge2\n');
}
if (deb_check(prefix: 'mysql-client', release: '3.1', reference: '4.0.24-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-client is vulnerable in Debian 3.1.\nUpgrade to mysql-client_4.0.24-10sarge2\n');
}
if (deb_check(prefix: 'mysql-common', release: '3.1', reference: '4.0.24-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-common is vulnerable in Debian 3.1.\nUpgrade to mysql-common_4.0.24-10sarge2\n');
}
if (deb_check(prefix: 'mysql-server', release: '3.1', reference: '4.0.24-10sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mysql-server is vulnerable in Debian 3.1.\nUpgrade to mysql-server_4.0.24-10sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
