# This script was automatically generated from the dsa-288
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Researchers discovered two flaws in OpenSSL, a Secure Socket Layer
(SSL) library and related cryptographic tools.  Applications that are
linked against this library are generally vulnerable to attacks that
could leak the server\'s private key or make the encrypted session
decryptable otherwise.  The Common Vulnerabilities and Exposures (CVE)
project identified the following vulnerabilities:
For the stable distribution (woody) these problems have been fixed in
version 0.9.6c-2.woody.3.
For the old stable distribution (potato) these problems have been
fixed in version 0.9.6c-0.potato.6.
For the unstable distribution (sid) these problems have been fixed in
version 0.9.7b-1 of openssl and version 0.9.6j-1 of openssl096.
We recommend that you upgrade your openssl packages immediately and
restart the applications that use OpenSSL.
Unfortunately, RSA blinding is not thread-safe and will cause failures
for programs that use threads and OpenSSL such as stunnel.  However,
since the proposed fix would change the binary interface (ABI),
programs that are dynamically linked against OpenSSL won\'t run
anymore.  This is a dilemma we can\'t solve.
You will have to decide whether you want the security update which is
not thread-safe and recompile all applications that apparently fail
after the upgrade, or fetch the additional source packages at the end
of this advisory, recompile it and use a thread-safe OpenSSL library
again, but also recompile all applications that make use of it (such
as apache-ssl, mod_ssl, ssh etc.).
However, since only very few packages use threads and link against the
OpenSSL library most users will be able to use packages from this
update without any problems.


Solution : http://www.debian.org/security/2003/dsa-288
Risk factor : High';

if (description) {
 script_id(15125);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "288");
 script_cve_id("CVE-2003-0131", "CVE-2003-0147");
 script_bugtraq_id(7101, 7148);
 script_xref(name: "CERT", value: "888801");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA288] DSA-288-1 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-288-1 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '2.2', reference: '0.9.6c-0.potato.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 2.2.\nUpgrade to libssl-dev_0.9.6c-0.potato.6\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '2.2', reference: '0.9.6c-0.potato.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 2.2.\nUpgrade to libssl0.9.6_0.9.6c-0.potato.6\n');
}
if (deb_check(prefix: 'openssl', release: '2.2', reference: '0.9.6c-0.potato.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 2.2.\nUpgrade to openssl_0.9.6c-0.potato.6\n');
}
if (deb_check(prefix: 'ssleay', release: '2.2', reference: '0.9.6c-0.potato.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 2.2.\nUpgrade to ssleay_0.9.6c-0.potato.6\n');
}
if (deb_check(prefix: 'libssl-dev', release: '3.0', reference: '0.9.6c-2.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.0.\nUpgrade to libssl-dev_0.9.6c-2.woody.3\n');
}
if (deb_check(prefix: 'libssl0.9.6', release: '3.0', reference: '0.9.6c-2.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 3.0.\nUpgrade to libssl0.9.6_0.9.6c-2.woody.3\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.0.\nUpgrade to openssl_0.9.6c-2.woody.3\n');
}
if (deb_check(prefix: 'ssleay', release: '3.0', reference: '0.9.6c-2.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ssleay is vulnerable in Debian 3.0.\nUpgrade to ssleay_0.9.6c-2.woody.3\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.1.\nUpgrade to openssl_0.9\n');
}
if (deb_check(prefix: 'openssl', release: '2.2', reference: '0.9.6c-0.potato.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian potato.\nUpgrade to openssl_0.9.6c-0.potato.6\n');
}
if (deb_check(prefix: 'openssl', release: '3.0', reference: '0.9.6c-2.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian woody.\nUpgrade to openssl_0.9.6c-2.woody.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
