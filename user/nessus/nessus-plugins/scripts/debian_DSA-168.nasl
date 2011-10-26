# This script was automatically generated from the dsa-168
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Wojciech Purczynski found out that it is possible for scripts to pass
arbitrary text to sendmail as commandline extension when sending a
mail through PHP even when safe_mode is turned on.  Passing 5th
argument should be disabled if PHP is configured in safe_mode, which
is the case for newer PHP versions and for the versions below.  This
does not affect PHP3, though.
Wojciech Purczynski also found out that arbitrary ASCII control
characters may be injected into string arguments of the mail() function.
If mail() arguments are taken from user\'s input it may give the user
ability to alter message content including mail headers.
Ulf Härnhammar discovered that file() and fopen() are vulnerable to
CRLF injection.  An attacker could use it to escape certain
restrictions and add arbitrary text to alleged HTTP requests that are
passed through.
However this only happens if something is passed to these functions
which is neither a valid file name nor a valid url.  Any string that
contains control chars cannot be a valid url.  Before you pass a
string that should be a url to any function you must use urlencode()
to encode it.
Three problems have been identified in PHP:
These problems have been fixed in version 3.0.18-23.1woody1 for PHP3
and 4.1.2-5 for PHP4 for the current stable distribution (woody), in
version 3.0.18-0potato1.2 for PHP3 and 4.0.3pl1-0potato4 for PHP4 in
the old stable distribution (potato) and in version 3.0.18-23.2 for
PHP3 and 4.2.3-3 for PHP4 for the unstable distribution (sid).
We recommend that you upgrade your PHP packages.


Solution : http://www.debian.org/security/2002/dsa-168
Risk factor : High';

if (description) {
 script_id(15005);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "168");
 script_cve_id("CVE-2002-0985", "CVE-2002-0986");
 script_bugtraq_id(5681);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA168] DSA-168-1 php");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-168-1 php");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'php3', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian 2.2.\nUpgrade to php3_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi is vulnerable in Debian 2.2.\nUpgrade to php3-cgi_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-gd', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-gd is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-gd_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-imap', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-imap is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-imap_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-ldap', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-ldap is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-ldap_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-magick', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-magick is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-magick_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-mhash', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mhash is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-mhash_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-mysql', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mysql is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-mysql_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-pgsql', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-pgsql is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-pgsql_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-snmp', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-snmp is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-snmp_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-cgi-xml', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-xml is vulnerable in Debian 2.2.\nUpgrade to php3-cgi-xml_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-dev', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-dev is vulnerable in Debian 2.2.\nUpgrade to php3-dev_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-doc', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-doc is vulnerable in Debian 2.2.\nUpgrade to php3-doc_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-gd', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-gd is vulnerable in Debian 2.2.\nUpgrade to php3-gd_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-imap', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-imap is vulnerable in Debian 2.2.\nUpgrade to php3-imap_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-ldap', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-ldap is vulnerable in Debian 2.2.\nUpgrade to php3-ldap_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-magick', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-magick is vulnerable in Debian 2.2.\nUpgrade to php3-magick_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-mhash', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mhash is vulnerable in Debian 2.2.\nUpgrade to php3-mhash_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-mysql', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mysql is vulnerable in Debian 2.2.\nUpgrade to php3-mysql_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-pgsql', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-pgsql is vulnerable in Debian 2.2.\nUpgrade to php3-pgsql_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-snmp', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-snmp is vulnerable in Debian 2.2.\nUpgrade to php3-snmp_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php3-xml', release: '2.2', reference: '3.0.18-0potato1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-xml is vulnerable in Debian 2.2.\nUpgrade to php3-xml_3.0.18-0potato1.2\n');
}
if (deb_check(prefix: 'php4', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 2.2.\nUpgrade to php4_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi is vulnerable in Debian 2.2.\nUpgrade to php4-cgi_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi-gd', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-gd is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-gd_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi-imap', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-imap is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-imap_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi-ldap', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-ldap is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-ldap_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi-mhash', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-mhash is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-mhash_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi-mysql', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-mysql is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-mysql_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi-pgsql', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-pgsql is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-pgsql_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi-snmp', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-snmp is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-snmp_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-cgi-xml', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi-xml is vulnerable in Debian 2.2.\nUpgrade to php4-cgi-xml_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-dev', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-dev is vulnerable in Debian 2.2.\nUpgrade to php4-dev_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-gd', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-gd is vulnerable in Debian 2.2.\nUpgrade to php4-gd_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-imap', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-imap is vulnerable in Debian 2.2.\nUpgrade to php4-imap_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-ldap', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-ldap is vulnerable in Debian 2.2.\nUpgrade to php4-ldap_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-mhash', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mhash is vulnerable in Debian 2.2.\nUpgrade to php4-mhash_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-mysql', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mysql is vulnerable in Debian 2.2.\nUpgrade to php4-mysql_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-pgsql', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-pgsql is vulnerable in Debian 2.2.\nUpgrade to php4-pgsql_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-snmp', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-snmp is vulnerable in Debian 2.2.\nUpgrade to php4-snmp_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'php4-xml', release: '2.2', reference: '4.0.3pl1-0potato4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-xml is vulnerable in Debian 2.2.\nUpgrade to php4-xml_4.0.3pl1-0potato4\n');
}
if (deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package caudium-php4 is vulnerable in Debian 3.0.\nUpgrade to caudium-php4_4.1.2-5\n');
}
if (deb_check(prefix: 'php3', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian 3.0.\nUpgrade to php3_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi is vulnerable in Debian 3.0.\nUpgrade to php3-cgi_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi-gd', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-gd is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-gd_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi-imap', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-imap is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-imap_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi-ldap', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-ldap is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-ldap_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi-magick', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-magick is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-magick_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi-mhash', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mhash is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-mhash_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi-mysql', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mysql is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-mysql_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi-snmp', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-snmp is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-snmp_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-cgi-xml', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-xml is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-xml_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-dev', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-dev is vulnerable in Debian 3.0.\nUpgrade to php3-dev_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-doc', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-doc is vulnerable in Debian 3.0.\nUpgrade to php3-doc_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-gd', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-gd is vulnerable in Debian 3.0.\nUpgrade to php3-gd_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-imap', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-imap is vulnerable in Debian 3.0.\nUpgrade to php3-imap_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-ldap', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-ldap is vulnerable in Debian 3.0.\nUpgrade to php3-ldap_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-magick', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-magick is vulnerable in Debian 3.0.\nUpgrade to php3-magick_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-mhash', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mhash is vulnerable in Debian 3.0.\nUpgrade to php3-mhash_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-mysql', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mysql is vulnerable in Debian 3.0.\nUpgrade to php3-mysql_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-snmp', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-snmp is vulnerable in Debian 3.0.\nUpgrade to php3-snmp_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php3-xml', release: '3.0', reference: '3.0.18-23.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-xml is vulnerable in Debian 3.0.\nUpgrade to php3-xml_3.0.18-23.1woody1\n');
}
if (deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 3.0.\nUpgrade to php4_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi is vulnerable in Debian 3.0.\nUpgrade to php4-cgi_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-curl is vulnerable in Debian 3.0.\nUpgrade to php4-curl_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-dev is vulnerable in Debian 3.0.\nUpgrade to php4-dev_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-domxml is vulnerable in Debian 3.0.\nUpgrade to php4-domxml_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-gd is vulnerable in Debian 3.0.\nUpgrade to php4-gd_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-imap is vulnerable in Debian 3.0.\nUpgrade to php4-imap_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-ldap is vulnerable in Debian 3.0.\nUpgrade to php4-ldap_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mcal is vulnerable in Debian 3.0.\nUpgrade to php4-mcal_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mhash is vulnerable in Debian 3.0.\nUpgrade to php4-mhash_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mysql is vulnerable in Debian 3.0.\nUpgrade to php4-mysql_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-odbc is vulnerable in Debian 3.0.\nUpgrade to php4-odbc_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-pear is vulnerable in Debian 3.0.\nUpgrade to php4-pear_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-recode is vulnerable in Debian 3.0.\nUpgrade to php4-recode_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-snmp is vulnerable in Debian 3.0.\nUpgrade to php4-snmp_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-sybase is vulnerable in Debian 3.0.\nUpgrade to php4-sybase_4.1.2-5\n');
}
if (deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-xslt is vulnerable in Debian 3.0.\nUpgrade to php4-xslt_4.1.2-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
