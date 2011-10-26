# This script was automatically generated from the dsa-789
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been found in PHP4, the
server-side, HTML-embedded scripting language.  The Common
Vulnerabilities and Exposures project identifies the following
problems:
    Eric Romang discovered insecure temporary files in the shtool
    utility shipped with PHP that can exploited by a local attacker to
    overwrite arbitrary files.  Only this vulnerability affects
    packages in oldstable.
    GulfTech has discovered that PEAR XML_RPC is vulnerable to a
    remote PHP code execution vulnerability that may allow an attacker
    to compromise a vulnerable server.
    Stefan Esser discovered another vulnerability in the XML-RPC
    libraries that allows injection of arbitrary PHP code into eval()
    statements.
For the old stable distribution (woody) these problems have been fixed in
version 4.1.2-7.woody5.
For the stable distribution (sarge) these problems have been fixed in
version 4.3.10-16.
For the unstable distribution (sid) these problems have been fixed in
version 4.4.0-2.
We recommend that you upgrade your PHP packages.


Solution : http://www.debian.org/security/2005/dsa-789
Risk factor : High';

if (description) {
 script_id(19532);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "789");
 script_cve_id("CVE-2005-1751", "CVE-2005-1921", "CVE-2005-2498");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA789] DSA-789-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-789-1 php4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'php4', release: '', reference: '4.4.0-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian .\nUpgrade to php4_4.4.0-2\n');
}
if (deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package caudium-php4 is vulnerable in Debian 3.0.\nUpgrade to caudium-php4_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 3.0.\nUpgrade to php4_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi is vulnerable in Debian 3.0.\nUpgrade to php4-cgi_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-curl is vulnerable in Debian 3.0.\nUpgrade to php4-curl_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-dev is vulnerable in Debian 3.0.\nUpgrade to php4-dev_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-domxml is vulnerable in Debian 3.0.\nUpgrade to php4-domxml_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-gd is vulnerable in Debian 3.0.\nUpgrade to php4-gd_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-imap is vulnerable in Debian 3.0.\nUpgrade to php4-imap_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-ldap is vulnerable in Debian 3.0.\nUpgrade to php4-ldap_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mcal is vulnerable in Debian 3.0.\nUpgrade to php4-mcal_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mhash is vulnerable in Debian 3.0.\nUpgrade to php4-mhash_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mysql is vulnerable in Debian 3.0.\nUpgrade to php4-mysql_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-odbc is vulnerable in Debian 3.0.\nUpgrade to php4-odbc_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-pear is vulnerable in Debian 3.0.\nUpgrade to php4-pear_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-recode is vulnerable in Debian 3.0.\nUpgrade to php4-recode_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-snmp is vulnerable in Debian 3.0.\nUpgrade to php4-snmp_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-sybase is vulnerable in Debian 3.0.\nUpgrade to php4-sybase_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-xslt is vulnerable in Debian 3.0.\nUpgrade to php4-xslt_4.1.2-7.woody5\n');
}
if (deb_check(prefix: 'libapache-mod-php4', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache-mod-php4 is vulnerable in Debian 3.1.\nUpgrade to libapache-mod-php4_4.3.10-16\n');
}
if (deb_check(prefix: 'libapache2-mod-php4', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libapache2-mod-php4 is vulnerable in Debian 3.1.\nUpgrade to libapache2-mod-php4_4.3.10-16\n');
}
if (deb_check(prefix: 'php4', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 3.1.\nUpgrade to php4_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-cgi', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi is vulnerable in Debian 3.1.\nUpgrade to php4-cgi_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-cli', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cli is vulnerable in Debian 3.1.\nUpgrade to php4-cli_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-common', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-common is vulnerable in Debian 3.1.\nUpgrade to php4-common_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-curl', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-curl is vulnerable in Debian 3.1.\nUpgrade to php4-curl_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-dev', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-dev is vulnerable in Debian 3.1.\nUpgrade to php4-dev_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-domxml', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-domxml is vulnerable in Debian 3.1.\nUpgrade to php4-domxml_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-gd', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-gd is vulnerable in Debian 3.1.\nUpgrade to php4-gd_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-imap', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-imap is vulnerable in Debian 3.1.\nUpgrade to php4-imap_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-ldap', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-ldap is vulnerable in Debian 3.1.\nUpgrade to php4-ldap_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-mcal', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mcal is vulnerable in Debian 3.1.\nUpgrade to php4-mcal_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-mhash', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mhash is vulnerable in Debian 3.1.\nUpgrade to php4-mhash_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-mysql', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mysql is vulnerable in Debian 3.1.\nUpgrade to php4-mysql_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-odbc', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-odbc is vulnerable in Debian 3.1.\nUpgrade to php4-odbc_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-pear', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-pear is vulnerable in Debian 3.1.\nUpgrade to php4-pear_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-recode', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-recode is vulnerable in Debian 3.1.\nUpgrade to php4-recode_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-snmp', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-snmp is vulnerable in Debian 3.1.\nUpgrade to php4-snmp_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-sybase', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-sybase is vulnerable in Debian 3.1.\nUpgrade to php4-sybase_4.3.10-16\n');
}
if (deb_check(prefix: 'php4-xslt', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-xslt is vulnerable in Debian 3.1.\nUpgrade to php4-xslt_4.3.10-16\n');
}
if (deb_check(prefix: 'php4', release: '3.1', reference: '4.3.10-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian sarge.\nUpgrade to php4_4.3.10-16\n');
}
if (deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7.woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian woody.\nUpgrade to php4_4.1.2-7.woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
