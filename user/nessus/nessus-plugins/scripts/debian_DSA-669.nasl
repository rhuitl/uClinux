# This script was automatically generated from the dsa-669
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in php4 which also apply to
the version of php3 in the stable Debian distribution.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    The memory_limit functionality allows remote attackers to execute
    arbitrary code under certain circumstances.
    The strip_tags function does not filter null (\\0) characters
    within tag names when restricting input to allowed tags, which
    allows dangerous tags to be processed by some web browsers which
    could lead to cross-site scripting (XSS) vulnerabilities.
For the stable distribution (woody) these problems have been fixed in
version 3.0.18-23.1woody2.
For the unstable distribution (sid) these problems have been fixed in
version 3.0.18-27.
We recommend that you upgrade your php3 packages.


Solution : http://www.debian.org/security/2005/dsa-669
Risk factor : High';

if (description) {
 script_id(16343);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "669");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA669] DSA-669-1 php3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-669-1 php3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'php3', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian 3.0.\nUpgrade to php3_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi is vulnerable in Debian 3.0.\nUpgrade to php3-cgi_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi-gd', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-gd is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-gd_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi-imap', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-imap is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-imap_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi-ldap', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-ldap is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-ldap_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi-magick', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-magick is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-magick_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi-mhash', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mhash is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-mhash_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi-mysql', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mysql is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-mysql_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi-snmp', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-snmp is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-snmp_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-cgi-xml', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-xml is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-xml_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-dev', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-dev is vulnerable in Debian 3.0.\nUpgrade to php3-dev_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-doc', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-doc is vulnerable in Debian 3.0.\nUpgrade to php3-doc_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-gd', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-gd is vulnerable in Debian 3.0.\nUpgrade to php3-gd_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-imap', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-imap is vulnerable in Debian 3.0.\nUpgrade to php3-imap_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-ldap', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-ldap is vulnerable in Debian 3.0.\nUpgrade to php3-ldap_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-magick', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-magick is vulnerable in Debian 3.0.\nUpgrade to php3-magick_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-mhash', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mhash is vulnerable in Debian 3.0.\nUpgrade to php3-mhash_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-mysql', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mysql is vulnerable in Debian 3.0.\nUpgrade to php3-mysql_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-snmp', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-snmp is vulnerable in Debian 3.0.\nUpgrade to php3-snmp_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3-xml', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-xml is vulnerable in Debian 3.0.\nUpgrade to php3-xml_3.0.18-23.1woody2\n');
}
if (deb_check(prefix: 'php3', release: '3.1', reference: '3.0.18-27')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian 3.1.\nUpgrade to php3_3.0.18-27\n');
}
if (deb_check(prefix: 'php3', release: '3.0', reference: '3.0.18-23.1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian woody.\nUpgrade to php3_3.0.18-23.1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
