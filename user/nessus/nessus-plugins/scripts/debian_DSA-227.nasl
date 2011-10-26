# This script was automatically generated from the dsa-227
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The SuSE Security Team reviewed critical parts of openldap2, an
implementation of the Lightweight Directory Access Protocol (LDAP)
version 2 and 3, and found several buffer overflows and other bugs
remote attackers could exploit to gain access on systems running
vulnerable LDAP servers.  In addition to these bugs, various local
exploitable bugs within the OpenLDAP2 libraries have been fixed.
For the current stable distribution (woody) these problems have been
fixed in version 2.0.23-6.3.
The old stable distribution (potato) does not contain OpenLDAP2
packages.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.27-3.
We recommend that you upgrade your openldap2 packages.


Solution : http://www.debian.org/security/2003/dsa-227
Risk factor : High';

if (description) {
 script_id(15064);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "227");
 script_cve_id("CVE-2002-1378", "CVE-2002-1379", "CVE-2002-1508");
 script_bugtraq_id(6328, 6620);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA227] DSA-227-1 openldap2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-227-1 openldap2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ldap-gateways', release: '3.0', reference: '2.0.23-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ldap-gateways is vulnerable in Debian 3.0.\nUpgrade to ldap-gateways_2.0.23-6.3\n');
}
if (deb_check(prefix: 'ldap-utils', release: '3.0', reference: '2.0.23-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ldap-utils is vulnerable in Debian 3.0.\nUpgrade to ldap-utils_2.0.23-6.3\n');
}
if (deb_check(prefix: 'libldap2', release: '3.0', reference: '2.0.23-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libldap2 is vulnerable in Debian 3.0.\nUpgrade to libldap2_2.0.23-6.3\n');
}
if (deb_check(prefix: 'libldap2-dev', release: '3.0', reference: '2.0.23-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libldap2-dev is vulnerable in Debian 3.0.\nUpgrade to libldap2-dev_2.0.23-6.3\n');
}
if (deb_check(prefix: 'slapd', release: '3.0', reference: '2.0.23-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package slapd is vulnerable in Debian 3.0.\nUpgrade to slapd_2.0.23-6.3\n');
}
if (deb_check(prefix: 'openldap2', release: '3.1', reference: '2.0.27-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openldap2 is vulnerable in Debian 3.1.\nUpgrade to openldap2_2.0.27-3\n');
}
if (deb_check(prefix: 'openldap2', release: '3.0', reference: '2.0.23-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openldap2 is vulnerable in Debian woody.\nUpgrade to openldap2_2.0.23-6.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
