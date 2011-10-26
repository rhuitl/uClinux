# This script was automatically generated from the dsa-729
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An iDEFENSE researcher discovered two problems in the image processing
functions of PHP, a server-side, HTML-embedded scripting language, of
which one is present in woody as well.  When reading a JPEG image, PHP
can be tricked into an endless loop due to insufficient input
validation.
For the stable distribution (woody) this problem has been fixed in
version 4.1.2-7.woody4.
For the testing distribution (sarge) these problems have been fixed in
version 4.3.10-10.
For the unstable distribution (sid) these problems have been fixed in
version 4.3.10-10.
We recommend that you upgrade your php4 packages.


Solution : http://www.debian.org/security/2005/dsa-729
Risk factor : High';

if (description) {
 script_id(18516);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "729");
 script_cve_id("CVE-2005-0525");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA729] DSA-729-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-729-1 php4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package caudium-php4 is vulnerable in Debian 3.0.\nUpgrade to caudium-php4_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 3.0.\nUpgrade to php4_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi is vulnerable in Debian 3.0.\nUpgrade to php4-cgi_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-curl is vulnerable in Debian 3.0.\nUpgrade to php4-curl_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-dev is vulnerable in Debian 3.0.\nUpgrade to php4-dev_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-domxml is vulnerable in Debian 3.0.\nUpgrade to php4-domxml_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-gd is vulnerable in Debian 3.0.\nUpgrade to php4-gd_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-imap is vulnerable in Debian 3.0.\nUpgrade to php4-imap_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-ldap is vulnerable in Debian 3.0.\nUpgrade to php4-ldap_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mcal is vulnerable in Debian 3.0.\nUpgrade to php4-mcal_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mhash is vulnerable in Debian 3.0.\nUpgrade to php4-mhash_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mysql is vulnerable in Debian 3.0.\nUpgrade to php4-mysql_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-odbc is vulnerable in Debian 3.0.\nUpgrade to php4-odbc_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-pear is vulnerable in Debian 3.0.\nUpgrade to php4-pear_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-recode is vulnerable in Debian 3.0.\nUpgrade to php4-recode_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-snmp is vulnerable in Debian 3.0.\nUpgrade to php4-snmp_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-sybase is vulnerable in Debian 3.0.\nUpgrade to php4-sybase_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-xslt is vulnerable in Debian 3.0.\nUpgrade to php4-xslt_4.1.2-7.woody4\n');
}
if (deb_check(prefix: 'php4', release: '3.1', reference: '4.3.10-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 3.1.\nUpgrade to php4_4.3.10-10\n');
}
if (deb_check(prefix: 'php4', release: '3.1', reference: '4.3.10-10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian sarge.\nUpgrade to php4_4.3.10-10\n');
}
if (deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7.woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian woody.\nUpgrade to php4_4.1.2-7.woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
