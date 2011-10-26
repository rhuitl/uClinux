# This script was automatically generated from the dsa-068
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The CERT advisory  lists a number of vulnerabilities in various
LDAP implementations, based on the 
results of the PROTOS LDAPv3 test suite. These tests found one
problem in OpenLDAP, a free LDAP implementation which is shipped
as part of Debian GNU/Linux 2.2.

The problem is that slapd did not handle packets which had
BER fields of invalid length and would crash if it received them.
An attacker could use this to mount a remote denial of service attack.

This problem has been fixed in version 1.2.12-1, and we recommend
that you upgrade your slapd package immediately.



Solution : http://www.debian.org/security/2001/dsa-068
Risk factor : High';

if (description) {
 script_id(14905);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "068");
 script_cve_id("CVE-2001-0977");
 script_bugtraq_id(3049);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA068] DSA-068-1 openldap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-068-1 openldap");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ldap-rfc', release: '2.2', reference: '1.2.12-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ldap-rfc is vulnerable in Debian 2.2.\nUpgrade to ldap-rfc_1.2.12-1\n');
}
if (deb_check(prefix: 'libopenldap-dev', release: '2.2', reference: '1.2.12-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libopenldap-dev is vulnerable in Debian 2.2.\nUpgrade to libopenldap-dev_1.2.12-1\n');
}
if (deb_check(prefix: 'libopenldap-runtime', release: '2.2', reference: '1.2.12-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libopenldap-runtime is vulnerable in Debian 2.2.\nUpgrade to libopenldap-runtime_1.2.12-1\n');
}
if (deb_check(prefix: 'libopenldap1', release: '2.2', reference: '1.2.12-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libopenldap1 is vulnerable in Debian 2.2.\nUpgrade to libopenldap1_1.2.12-1\n');
}
if (deb_check(prefix: 'openldap-gateways', release: '2.2', reference: '1.2.12-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openldap-gateways is vulnerable in Debian 2.2.\nUpgrade to openldap-gateways_1.2.12-1\n');
}
if (deb_check(prefix: 'openldap-utils', release: '2.2', reference: '1.2.12-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openldap-utils is vulnerable in Debian 2.2.\nUpgrade to openldap-utils_1.2.12-1\n');
}
if (deb_check(prefix: 'openldapd', release: '2.2', reference: '1.2.12-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openldapd is vulnerable in Debian 2.2.\nUpgrade to openldapd_1.2.12-1\n');
}
if (w) { security_hole(port: 0, data: desc); }
