# This script was automatically generated from the dsa-393
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Dr. Stephen Henson ("steve@openssl.org"), using a test suite
provided by NISCC ("http://www.niscc.gov.uk/"), discovered a number of
errors in the OpenSSL
ASN1 code.  Combined with an error that causes the OpenSSL code to parse
client certificates even when it should not, these errors can cause a
denial of service (DoS) condition on a system using the OpenSSL code,
depending on how that code is used. For example, even though apache-ssl
and ssh link to OpenSSL libraries, they should not be affected by this
vulnerability. However, other SSL-enabled applications may be
vulnerable and an OpenSSL upgrade is recommended.
For the current stable distribution (woody) these problems have been
fixed in version 0.9.6c-2.woody.4.
For the unstable distribution (sid) these problems have been fixed in
version 0.9.7c-1.
We recommend that you update your openssl package. Note that you will
need to restart services which use the libssl library for this update
to take effect.


Solution : http://www.debian.org/security/2003/dsa-393
Risk factor : High';

if (description) {
 script_id(15230);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "393");
 script_cve_id("CVE-2003-0543", "CVE-2003-0544");
 script_bugtraq_id(8732);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA393] DSA-393-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-393-1 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.0.\nUpgrade to libssl-dev_0.9.6c-2.woody.4\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 3.0.\nUpgrade to libssl0.9.6_0.9.6c-2.woody.4\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.0.\nUpgrade to openssl_0.9.6c-2.woody.4\n');
}
if (deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 3.0.\nUpgrade to ssleay_0.9.6c-2.woody.4\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7c-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.1.\nUpgrade to openssl_0.9.7c-1\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian woody.\nUpgrade to openssl_0.9.6c-2.woody.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
