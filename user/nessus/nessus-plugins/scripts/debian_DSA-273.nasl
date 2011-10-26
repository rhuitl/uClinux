# This script was automatically generated from the dsa-273
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A cryptographic weakness in version 4 of the Kerberos protocol allows
an attacker to use a chosen-plaintext attack to impersonate any
principal in a realm.  Additional cryptographic weaknesses in the krb4
implementation permit the use of cut-and-paste attacks to fabricate
krb4 tickets for unauthorized client principals if triple-DES keys are
used to key krb4 services.  These attacks can subvert a site\'s entire
Kerberos authentication infrastructure.
For the stable distribution (woody) this problem has been
fixed in version 1.1-8-2.3.
For the old stable distribution (potato) this problem has been
fixed in version 1.0-2.3.
For the unstable distribution (sid) this problem has been
fixed in version 1.2.2-1.
We recommend that you upgrade your krb4 packages immediately.


Solution : http://www.debian.org/security/2003/dsa-273
Risk factor : High';

if (description) {
 script_id(15110);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "273");
 script_cve_id("CVE-2003-0138", "CVE-2003-0139");
 script_xref(name: "CERT", value: "442569");
 script_xref(name: "CERT", value: "623217");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA273] DSA-273-1 krb4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-273-1 krb4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kerberos4kth-clients', release: '2.2', reference: '1.0-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-clients is vulnerable in Debian 2.2.\nUpgrade to kerberos4kth-clients_1.0-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-dev', release: '2.2', reference: '1.0-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-dev is vulnerable in Debian 2.2.\nUpgrade to kerberos4kth-dev_1.0-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-kdc', release: '2.2', reference: '1.0-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-kdc is vulnerable in Debian 2.2.\nUpgrade to kerberos4kth-kdc_1.0-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-services', release: '2.2', reference: '1.0-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-services is vulnerable in Debian 2.2.\nUpgrade to kerberos4kth-services_1.0-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-user', release: '2.2', reference: '1.0-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-user is vulnerable in Debian 2.2.\nUpgrade to kerberos4kth-user_1.0-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-x11', release: '2.2', reference: '1.0-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-x11 is vulnerable in Debian 2.2.\nUpgrade to kerberos4kth-x11_1.0-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth1', release: '2.2', reference: '1.0-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth1 is vulnerable in Debian 2.2.\nUpgrade to kerberos4kth1_1.0-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-clients', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-clients is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-clients_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-clients-x', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-clients-x is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-clients-x_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-dev', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-dev is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-dev_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-dev-common', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-dev-common is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-dev-common_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-docs', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-docs is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-docs_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-kdc', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-kdc is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-kdc_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-kip', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-kip is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-kip_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-servers', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-servers is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-servers_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-servers-x', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-servers-x is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-servers-x_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-services', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-services is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-services_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-user', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-user is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-user_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth-x11', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth-x11 is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth-x11_1.1-8-2.3\n');
}
if (deb_check(prefix: 'kerberos4kth1', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kerberos4kth1 is vulnerable in Debian 3.0.\nUpgrade to kerberos4kth1_1.1-8-2.3\n');
}
if (deb_check(prefix: 'libacl1-kerberos4kth', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libacl1-kerberos4kth is vulnerable in Debian 3.0.\nUpgrade to libacl1-kerberos4kth_1.1-8-2.3\n');
}
if (deb_check(prefix: 'libkadm1-kerberos4kth', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkadm1-kerberos4kth is vulnerable in Debian 3.0.\nUpgrade to libkadm1-kerberos4kth_1.1-8-2.3\n');
}
if (deb_check(prefix: 'libkdb-1-kerberos4kth', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkdb-1-kerberos4kth is vulnerable in Debian 3.0.\nUpgrade to libkdb-1-kerberos4kth_1.1-8-2.3\n');
}
if (deb_check(prefix: 'libkrb-1-kerberos4kth', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkrb-1-kerberos4kth is vulnerable in Debian 3.0.\nUpgrade to libkrb-1-kerberos4kth_1.1-8-2.3\n');
}
if (deb_check(prefix: 'krb4', release: '3.1', reference: '1.2.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb4 is vulnerable in Debian 3.1.\nUpgrade to krb4_1.2.2-1\n');
}
if (deb_check(prefix: 'krb4', release: '2.2', reference: '1.0-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb4 is vulnerable in Debian potato.\nUpgrade to krb4_1.0-2.3\n');
}
if (deb_check(prefix: 'krb4', release: '3.0', reference: '1.1-8-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package krb4 is vulnerable in Debian woody.\nUpgrade to krb4_1.1-8-2.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
