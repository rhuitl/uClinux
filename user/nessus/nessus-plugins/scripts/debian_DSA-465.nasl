# This script was automatically generated from the dsa-465
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities were discovered in openssl, an implementation of
the SSL protocol, using the Codenomicon TLS Test Tool.  More
information can be found in the following <a
href="http://www.uniras.gov.uk/vuls/2004/224012/index.htm">NISCC
Vulnerability Advisory</a> and this <a
href="http://www.openssl.org/news/secadv_20040317.txt">OpenSSL
advisory</a>.  The Common Vulnerabilities and Exposures project
identified the following vulnerabilities:
   Null-pointer assignment in the
   do_change_cipher_spec() function.  A remote attacker could perform
   a carefully crafted SSL/TLS handshake against a server that used
   the OpenSSL library in such a way as to cause OpenSSL to crash.
   Depending on the application this could lead to a denial of
   service.
   A bug in older versions of OpenSSL 0.9.6 that
   can lead to a Denial of Service attack (infinite loop).
For the stable distribution (woody) these problems have been fixed in
openssl version 0.9.6c-2.woody.6, openssl094 version 0.9.4-6.woody.4
and openssl095 version 0.9.5a-6.woody.5.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you update your openssl package.


Solution : http://www.debian.org/security/2004/dsa-465
Risk factor : High';

if (description) {
 script_id(15302);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "465");
 script_cve_id("CVE-2004-0079", "CVE-2004-0081");
 script_bugtraq_id(9899);
 script_xref(name: "CERT", value: "288574");
 script_xref(name: "CERT", value: "465542");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA465] DSA-465-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-465-1 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.0.\nUpgrade to libssl-dev_0.9.6c-2.woody.6\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 3.0.\nUpgrade to libssl0.9.6_0.9.6c-2.woody.6\n');
}
if (deb_check(prefix: 'libssl09', release: '3.0', reference: '0.9.4-6.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl09 is vulnerable in Debian 3.0.\nUpgrade to libssl09_0.9.4-6.woody.3\n');
}
if (deb_check(prefix: 'libssl095a', release: '3.0', reference: '0.9.5a-6.woody.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl095a is vulnerable in Debian 3.0.\nUpgrade to libssl095a_0.9.5a-6.woody.5\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.0.\nUpgrade to openssl_0.9.6c-2.woody.6\n');
}
if (deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 3.0.\nUpgrade to ssleay_0.9.6c-2.woody.6\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian woody.\nUpgrade to openssl_0.9.6c-2.woody\n');
}
if (w) { security_hole(port: 0, data: desc); }
