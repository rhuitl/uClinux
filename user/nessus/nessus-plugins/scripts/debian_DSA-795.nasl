# This script was automatically generated from the dsa-795
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
infamous42md reported that proftpd suffers from two format string
vulnerabilities. In the first, a user with the ability to create a
directory could trigger the format string error if there is a
proftpd shutdown message configured to use the "%C", "%R", or "%U"
variables. In the second, the error is triggered if mod_sql is used
to retrieve messages from a database and if format strings have been
inserted into the database by a user with permission to do so.
The old stable distribution (woody) is not affected by these
vulnerabilities.
For the stable distribution (sarge) this problem has been fixed in
version 1.2.10-15sarge1. There was an error in the packages originally
prepared for i386, which was corrected in 1.2.10-15sarge1.0.1 for i386.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.10-20.
We recommend that you upgrade your proftpd package.


Solution : http://www.debian.org/security/2005/dsa-795
Risk factor : High';

if (description) {
 script_id(19565);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "795");
 script_cve_id("CVE-2005-2390");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA795] DSA-795-2 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-795-2 proftpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'proftpd', release: '', reference: '1.2.10-20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd is vulnerable in Debian .\nUpgrade to proftpd_1.2.10-20\n');
}
if (deb_check(prefix: 'proftpd', release: '3.1', reference: '1.2.10-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd is vulnerable in Debian 3.1.\nUpgrade to proftpd_1.2.10-15sarge1\n');
}
if (deb_check(prefix: 'proftpd-common', release: '3.1', reference: '1.2.10-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-common is vulnerable in Debian 3.1.\nUpgrade to proftpd-common_1.2.10-15sarge1\n');
}
if (deb_check(prefix: 'proftpd-doc', release: '3.1', reference: '1.2.10-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-doc is vulnerable in Debian 3.1.\nUpgrade to proftpd-doc_1.2.10-15sarge1\n');
}
if (deb_check(prefix: 'proftpd-ldap', release: '3.1', reference: '1.2.10-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-ldap is vulnerable in Debian 3.1.\nUpgrade to proftpd-ldap_1.2.10-15sarge1\n');
}
if (deb_check(prefix: 'proftpd-mysql', release: '3.1', reference: '1.2.10-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-mysql is vulnerable in Debian 3.1.\nUpgrade to proftpd-mysql_1.2.10-15sarge1\n');
}
if (deb_check(prefix: 'proftpd-pgsql', release: '3.1', reference: '1.2.10-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd-pgsql is vulnerable in Debian 3.1.\nUpgrade to proftpd-pgsql_1.2.10-15sarge1\n');
}
if (deb_check(prefix: 'proftpd', release: '3.1', reference: '1.2.10-15sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package proftpd is vulnerable in Debian sarge.\nUpgrade to proftpd_1.2.10-15sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
