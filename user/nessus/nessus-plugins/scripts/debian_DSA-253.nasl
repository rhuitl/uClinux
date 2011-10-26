# This script was automatically generated from the dsa-253
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in OpenSSL, a Secure Socket Layer
(SSL) implementation.  In an upcoming paper, Brice Canvel (EPFL),
Alain Hiltgen (UBS), Serge Vaudenay (EPFL), and Martin Vuagnoux (EPFL,
Ilion) describe and demonstrate a timing-based attack on CBC cipher
suites used in SSL and TLS.  OpenSSL has been found to be vulnerable to
this attack.
For the stable distribution (woody) this problem has been
fixed in version 0.9.6c-2.woody.2.
For the old stable distribution (potato) this problem has been fixed
in version 0.9.6c-0.potato.5.  Please note that this updates the
version from potato-proposed-updates that supersedes the version in
potato.
For the unstable distribution (sid) this problem has been fixed in
version 0.9.7a-1.
We recommend that you upgrade your openssl packages.


Solution : http://www.debian.org/security/2003/dsa-253
Risk factor : High';

if (description) {
 script_id(15090);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "253");
 script_cve_id("CVE-2003-0078");
 script_bugtraq_id(6884);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA253] DSA-253-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-253-1 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '2.2', reference: '0.9.6c-0.potato.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 2.2.\nUpgrade to libssl-dev_0.9.6c-0.potato.5\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '2.2', reference: '0.9.6c-0.potato.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 2.2.\nUpgrade to libssl0.9.6_0.9.6c-0.potato.5\n');
}
if (deb_check(prefix: 'openssl', release: '2.2', reference: '0.9.6c-0.potato.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 2.2.\nUpgrade to openssl_0.9.6c-0.potato.5\n');
}
if (deb_check(prefix: 'ssleay', release: '2.2', reference: '0.9.6c-0.potato.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 2.2.\nUpgrade to ssleay_0.9.6c-0.potato.5\n');
}
if (deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.0.\nUpgrade to libssl-dev_0.9.6c-2.woody.2\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 3.0.\nUpgrade to libssl0.9.6_0.9.6c-2.woody.2\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.0.\nUpgrade to openssl_0.9.6c-2.woody.2\n');
}
if (deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 3.0.\nUpgrade to ssleay_0.9.6c-2.woody.2\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7a-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.1.\nUpgrade to openssl_0.9.7a-1\n');
}
if (deb_check(prefix: 'openssl', release: '2.2', reference: '0.9.6c-0.potato.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian potato.\nUpgrade to openssl_0.9.6c-0.potato.5\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian woody.\nUpgrade to openssl_0.9.6c-2.woody.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
