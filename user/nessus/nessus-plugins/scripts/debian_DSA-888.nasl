# This script was automatically generated from the dsa-888
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Yutaka Oiwa discovered a vulnerability in the Open Secure Socket Layer
(OpenSSL) library that can allow an attacker to perform active
protocol-version rollback attacks that could lead to the use of the
weaker SSL 2.0 protocol even though both ends support SSL 3.0 or TLS
1.0.
The following matrix explains which version in which distribution has
this problem corrected.
We recommend that you upgrade your libssl packages.


Solution : http://www.debian.org/security/2005/dsa-888
Risk factor : High';

if (description) {
 script_id(22754);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "888");
 script_cve_id("CVE-2005-2969");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA888] DSA-888-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-888-1 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.0.\nUpgrade to libssl-dev_0.9.6c-2.woody.8\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 3.0.\nUpgrade to libssl0.9.6_0.9.6c-2.woody.8\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.0.\nUpgrade to openssl_0.9.6c-2.woody.8\n');
}
if (deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 3.0.\nUpgrade to ssleay_0.9.6c-2.woody.8\n');
}
if (deb_check(prefix: 'libssl-dev', release: '3.1', reference: '0.9.7e-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.1.\nUpgrade to libssl-dev_0.9.7e-3sarge1\n');
}
if (deb_check(prefix: 'libssl0.9.7', release: '3.1', reference: '0.9.7e-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.7 is vulnerable in Debian 3.1.\nUpgrade to libssl0.9.7_0.9.7e-3sarge1\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.1.\nUpgrade to openssl_0.9.7e-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
