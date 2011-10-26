# This script was automatically generated from the dsa-531
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities were discovered in php4:
   The memory_limit functionality in PHP 4.x up to
   4.3.7, and 5.x up to 5.0.0RC3, under certain conditions such as
   when register_globals is enabled, allows remote attackers to
   execute arbitrary code by triggering a memory_limit abort during
   execution of the zend_hash_init function and overwriting a
   HashTable destructor pointer before the initialization of key data
   structures is complete.
   The strip_tags function in PHP 4.x up to 4.3.7, and
   5.x up to 5.0.0RC3, does not filter null (\\0) characters within tag
   names when restricting input to allowed tags, which allows
   dangerous tags to be processed by web browsers such as Internet
   Explorer and Safari, which ignore null characters and facilitate
   the exploitation of cross-site scripting (XSS) vulnerabilities.
For the current stable distribution (woody), these problems have been
fixed in version 4.1.2-7.
For the unstable distribution (sid), these problems have been fixed in
version 4:4.3.8-1.
We recommend that you update your php4 package.


Solution : http://www.debian.org/security/2004/dsa-531
Risk factor : High';

if (description) {
 script_id(15368);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "531");
 script_cve_id("CVE-2004-0594", "CVE-2004-0595");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA531] DSA-531-1 php4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-531-1 php4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'caudium-php4', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package caudium-php4 is vulnerable in Debian 3.0.\nUpgrade to caudium-php4_4.1.2-7\n');
}
if (deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 3.0.\nUpgrade to php4_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-cgi', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-cgi is vulnerable in Debian 3.0.\nUpgrade to php4-cgi_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-curl', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-curl is vulnerable in Debian 3.0.\nUpgrade to php4-curl_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-dev', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-dev is vulnerable in Debian 3.0.\nUpgrade to php4-dev_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-domxml', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-domxml is vulnerable in Debian 3.0.\nUpgrade to php4-domxml_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-gd', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-gd is vulnerable in Debian 3.0.\nUpgrade to php4-gd_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-imap', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-imap is vulnerable in Debian 3.0.\nUpgrade to php4-imap_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-ldap', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-ldap is vulnerable in Debian 3.0.\nUpgrade to php4-ldap_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-mcal', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mcal is vulnerable in Debian 3.0.\nUpgrade to php4-mcal_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-mhash', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mhash is vulnerable in Debian 3.0.\nUpgrade to php4-mhash_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-mysql', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-mysql is vulnerable in Debian 3.0.\nUpgrade to php4-mysql_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-odbc', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-odbc is vulnerable in Debian 3.0.\nUpgrade to php4-odbc_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-pear', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-pear is vulnerable in Debian 3.0.\nUpgrade to php4-pear_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-recode', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-recode is vulnerable in Debian 3.0.\nUpgrade to php4-recode_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-snmp', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-snmp is vulnerable in Debian 3.0.\nUpgrade to php4-snmp_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-sybase', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-sybase is vulnerable in Debian 3.0.\nUpgrade to php4-sybase_4.1.2-7\n');
}
if (deb_check(prefix: 'php4-xslt', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4-xslt is vulnerable in Debian 3.0.\nUpgrade to php4-xslt_4.1.2-7\n');
}
if (deb_check(prefix: 'php4', release: '3.1', reference: '4.3.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian 3.1.\nUpgrade to php4_4.3.8-1\n');
}
if (deb_check(prefix: 'php4', release: '3.0', reference: '4.1.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package php4 is vulnerable in Debian woody.\nUpgrade to php4_4.1.2-7\n');
}
if (w) { security_hole(port: 0, data: desc); }
