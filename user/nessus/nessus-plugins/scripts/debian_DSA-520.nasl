# This script was automatically generated from the dsa-520
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
In their advisory MITKRB5-SA-2004-001, the MIT Kerberos announced the
existence of buffer overflow vulnerabilities in the
krb5_aname_to_localname function.  This function is only used if
aname_to_localname is enabled in the configuration (this is not
enabled by default).
For the current stable distribution (woody), this problem has been
fixed in version 1.2.4-5woody5.
For the unstable distribution (sid), this problem has been fixed in
version 1.3.3-2.
We recommend that you update your krb5 package.


Solution : http://www.debian.org/security/2004/dsa-520
Risk factor : High';

if (description) {
 script_id(15357);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0017");
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "520");
 script_cve_id("CVE-2004-0523");
 script_bugtraq_id(10448);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA520] DSA-520-1 krb5");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-520-1 krb5");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'krb5-admin-server', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-admin-server is vulnerable in Debian 3.0.\nUpgrade to krb5-admin-server_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'krb5-clients', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-clients is vulnerable in Debian 3.0.\nUpgrade to krb5-clients_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'krb5-doc', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-doc is vulnerable in Debian 3.0.\nUpgrade to krb5-doc_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'krb5-ftpd', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-ftpd is vulnerable in Debian 3.0.\nUpgrade to krb5-ftpd_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'krb5-kdc', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-kdc is vulnerable in Debian 3.0.\nUpgrade to krb5-kdc_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'krb5-rsh-server', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-rsh-server is vulnerable in Debian 3.0.\nUpgrade to krb5-rsh-server_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'krb5-telnetd', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-telnetd is vulnerable in Debian 3.0.\nUpgrade to krb5-telnetd_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'krb5-user', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5-user is vulnerable in Debian 3.0.\nUpgrade to krb5-user_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'libkadm55', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm55 is vulnerable in Debian 3.0.\nUpgrade to libkadm55_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'libkrb5-dev', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb5-dev is vulnerable in Debian 3.0.\nUpgrade to libkrb5-dev_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'libkrb53', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb53 is vulnerable in Debian 3.0.\nUpgrade to libkrb53_1.2.4-5woody5\n');
}
if (deb_check(prefix: 'krb5', release: '3.1', reference: '1.3.3-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian 3.1.\nUpgrade to krb5_1.3.3-2\n');
}
if (deb_check(prefix: 'krb5', release: '3.0', reference: '1.2.4-5woody5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb5 is vulnerable in Debian woody.\nUpgrade to krb5_1.2.4-5woody5\n');
}
if (w) { security_hole(port: 0, data: desc); }
