# This script was automatically generated from the dsa-708
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An iDEFENSE researcher discovered two problems in the image processing
functions of PHP, a server-side, HTML-embedded scripting language, of
which one is present in PHP3 as well.  When reading a JPEG image, PHP
can be tricked into an endless loop due to insufficient input
validation.
For the stable distribution (woody) this problem has been fixed in
version 3.0.18-23.1woody3.
For the unstable distribution (sid) this problem has been fixed in
version 3.0.18-31.
We recommend that you upgrade your php3 package.


Solution : http://www.debian.org/security/2005/dsa-708
Risk factor : High';

if (description) {
 script_id(18053);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "708");
 script_cve_id("CVE-2005-0525");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA708] DSA-708-1 php3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-708-1 php3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'php3', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian 3.0.\nUpgrade to php3_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi is vulnerable in Debian 3.0.\nUpgrade to php3-cgi_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi-gd', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-gd is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-gd_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi-imap', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-imap is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-imap_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi-ldap', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-ldap is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-ldap_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi-magick', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-magick is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-magick_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi-mhash', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mhash is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-mhash_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi-mysql', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-mysql is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-mysql_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi-snmp', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-snmp is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-snmp_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-cgi-xml', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-cgi-xml is vulnerable in Debian 3.0.\nUpgrade to php3-cgi-xml_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-dev', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-dev is vulnerable in Debian 3.0.\nUpgrade to php3-dev_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-doc', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-doc is vulnerable in Debian 3.0.\nUpgrade to php3-doc_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-gd', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-gd is vulnerable in Debian 3.0.\nUpgrade to php3-gd_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-imap', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-imap is vulnerable in Debian 3.0.\nUpgrade to php3-imap_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-ldap', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-ldap is vulnerable in Debian 3.0.\nUpgrade to php3-ldap_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-magick', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-magick is vulnerable in Debian 3.0.\nUpgrade to php3-magick_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-mhash', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mhash is vulnerable in Debian 3.0.\nUpgrade to php3-mhash_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-mysql', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-mysql is vulnerable in Debian 3.0.\nUpgrade to php3-mysql_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-snmp', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-snmp is vulnerable in Debian 3.0.\nUpgrade to php3-snmp_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3-xml', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3-xml is vulnerable in Debian 3.0.\nUpgrade to php3-xml_3.0.18-23.1woody3\n');
}
if (deb_check(prefix: 'php3', release: '3.1', reference: '3.0.18-31')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian 3.1.\nUpgrade to php3_3.0.18-31\n');
}
if (deb_check(prefix: 'php3', release: '3.0', reference: '3.0.18-23.1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php3 is vulnerable in Debian woody.\nUpgrade to php3_3.0.18-23.1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
