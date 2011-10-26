# This script was automatically generated from the dsa-363
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The postfix mail transport agent in Debian 3.0 contains two
vulnerabilities:
For the current stable distribution (woody) these problems have been
fixed in version 1.1.11-0.woody3.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you update your postfix package.


Solution : http://www.debian.org/security/2003/dsa-363
Risk factor : High';

if (description) {
 script_id(15200);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "363");
 script_cve_id("CVE-2003-0468", "CVE-2003-0540");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA363] DSA-363-1 postfix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-363-1 postfix");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'postfix', release: '3.0', reference: '1.1.11-0.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postfix is vulnerable in Debian 3.0.\nUpgrade to postfix_1.1.11-0.woody3\n');
}
if (deb_check(prefix: 'postfix-dev', release: '3.0', reference: '1.1.11-0.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postfix-dev is vulnerable in Debian 3.0.\nUpgrade to postfix-dev_1.1.11-0.woody3\n');
}
if (deb_check(prefix: 'postfix-doc', release: '3.0', reference: '1.1.11-0.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postfix-doc is vulnerable in Debian 3.0.\nUpgrade to postfix-doc_1.1.11-0.woody3\n');
}
if (deb_check(prefix: 'postfix-ldap', release: '3.0', reference: '1.1.11-0.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postfix-ldap is vulnerable in Debian 3.0.\nUpgrade to postfix-ldap_1.1.11-0.woody3\n');
}
if (deb_check(prefix: 'postfix-mysql', release: '3.0', reference: '1.1.11-0.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postfix-mysql is vulnerable in Debian 3.0.\nUpgrade to postfix-mysql_1.1.11-0.woody3\n');
}
if (deb_check(prefix: 'postfix-pcre', release: '3.0', reference: '1.1.11-0.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postfix-pcre is vulnerable in Debian 3.0.\nUpgrade to postfix-pcre_1.1.11-0.woody3\n');
}
if (deb_check(prefix: 'postfix', release: '3.0', reference: '1.1.11-0.woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package postfix is vulnerable in Debian woody.\nUpgrade to postfix_1.1.11-0.woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
