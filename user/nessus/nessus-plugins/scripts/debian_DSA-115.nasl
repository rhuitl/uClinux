# This script was automatically generated from the dsa-115
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser, who is also a member of the PHP team, found several
flaws
in the way PHP handles multipart/form-data POST requests (as
described in RFC1867) known as POST fileuploads.  Each of the flaws
could allow an attacker to execute arbitrary code on the victim\'s
system.
For PHP3 flaws contain a broken boundary check and an arbitrary heap
overflow.  For PHP4 they consist of a broken boundary check and a heap
off by one error.
For the stable release of Debian these problems are fixed in version
3.0.18-0potato1.1 of PHP3 and version 4.0.3pl1-0potato3 of PHP4.
For the unstable and testing release of Debian these problems are
fixed in version 3.0.18-22 of PHP3 and version 4.1.2-1 of PHP4.
There is no PHP4 in the stable and unstable distribution for the arm
architecture due to a compiler error.
We recommend that you upgrade your PHP packages immediately.


Solution : http://www.debian.org/security/2002/dsa-115
Risk factor : High';

if (description) {
 script_id(14952);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "115");
 script_cve_id("CVE-2002-0081");
 script_bugtraq_id(4183);
 script_xref(name: "CERT", value: "297363");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA115] DSA-115-1 php");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-115-1 php");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'php3', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian 2.2.\nUpgrade to php3_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi is vulnerable in Debian 2.2.\nUpgrade to php3-cgi_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-gd', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-gd is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-gd_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-imap', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-imap is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-imap_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-ldap', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-ldap is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-ldap_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-magick', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-magick is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-magick_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-mhash', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mhash is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-mhash_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-mysql', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mysql is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-mysql_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-pgsql', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-pgsql is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-pgsql_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-snmp', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-snmp is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-snmp_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-cgi-xml', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-xml is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-xml_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-dev', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-dev is vulnerable in Debian 2.2.\nUpgrade to php3-dev_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-doc', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-doc is vulnerable in Debian 2.2.\nUpgrade to php3-doc_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-gd', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-gd is vulnerable in Debian 2.2.\nUpgrade to php3-gd_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-imap', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-imap is vulnerable in Debian 2.2.\nUpgrade to php3-imap_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-ldap', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-ldap is vulnerable in Debian 2.2.\nUpgrade to php3-ldap_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-magick', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-magick is vulnerable in Debian 2.2.\nUpgrade to php3-magick_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-mhash', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mhash is vulnerable in Debian 2.2.\nUpgrade to php3-mhash_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-mysql', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mysql is vulnerable in Debian 2.2.\nUpgrade to php3-mysql_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-pgsql', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-pgsql is vulnerable in Debian 2.2.\nUpgrade to php3-pgsql_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-snmp', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-snmp is vulnerable in Debian 2.2.\nUpgrade to php3-snmp_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php3-xml', release: '2.2', reference: '3.0.18-0potato1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-xml is vulnerable in Debian 2.2.\nUpgrade to php3-xml_3.0.18-0potato1.1\n');
}
if (deb_check(prefix: 'php4', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 2.2.\nUpgrade to php4_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi is vulnerable in Debian 2.2.\nUpgrade to php4-cgi_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi-gd', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-gd is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-gd_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi-imap', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-imap is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-imap_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi-ldap', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-ldap is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-ldap_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi-mhash', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-mhash is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-mhash_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi-mysql', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-mysql is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-mysql_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi-pgsql', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-pgsql is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-pgsql_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi-snmp', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-snmp is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-snmp_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-cgi-xml', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-xml is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-xml_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-dev', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-dev is vulnerable in Debian 2.2.\nUpgrade to php4-dev_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-gd', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-gd is vulnerable in Debian 2.2.\nUpgrade to php4-gd_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-imap', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-imap is vulnerable in Debian 2.2.\nUpgrade to php4-imap_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-ldap', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-ldap is vulnerable in Debian 2.2.\nUpgrade to php4-ldap_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-mhash', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mhash is vulnerable in Debian 2.2.\nUpgrade to php4-mhash_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-mysql', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mysql is vulnerable in Debian 2.2.\nUpgrade to php4-mysql_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-pgsql', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-pgsql is vulnerable in Debian 2.2.\nUpgrade to php4-pgsql_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-snmp', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-snmp is vulnerable in Debian 2.2.\nUpgrade to php4-snmp_4.0.3pl1-0potato3\n');
}
if (deb_check(prefix: 'php4-xml', release: '2.2', reference: '4.0.3pl1-0potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-xml is vulnerable in Debian 2.2.\nUpgrade to php4-xml_4.0.3pl1-0potato3\n');
}
if (w) { security_hole(port: 0, data: desc); }
