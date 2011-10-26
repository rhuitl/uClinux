# This script was automatically generated from the dsa-986
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Evgeny Legerov discovered several out-of-bounds memory accesses in the
DER decoding component of the Tiny ASN.1 Library, which is
also present and used in GnuTLS, the GNU implementation for Transport
Layer Security (TLS) 1.0 and Secure Sockets Layer (SSL) 3.0 protocols
and which allows attackers to crash the DER decoder and possibly
execute arbitrary code.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 1.0.16-13.2.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your gnutls packages.


Solution : http://www.debian.org/security/2006/dsa-986
Risk factor : High';

if (description) {
 script_id(22852);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "986");
 script_cve_id("CVE-2006-0645");
 script_bugtraq_id(16568);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA986] DSA-986-1 gnutls11");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-986-1 gnutls11");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gnutls-bin', release: '3.1', reference: '1.0.16-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnutls-bin is vulnerable in Debian 3.1.\nUpgrade to gnutls-bin_1.0.16-13.2\n');
}
if (deb_check(prefix: 'libgnutls11', release: '3.1', reference: '1.0.16-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgnutls11 is vulnerable in Debian 3.1.\nUpgrade to libgnutls11_1.0.16-13.2\n');
}
if (deb_check(prefix: 'libgnutls11-dbg', release: '3.1', reference: '1.0.16-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgnutls11-dbg is vulnerable in Debian 3.1.\nUpgrade to libgnutls11-dbg_1.0.16-13.2\n');
}
if (deb_check(prefix: 'libgnutls11-dev', release: '3.1', reference: '1.0.16-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgnutls11-dev is vulnerable in Debian 3.1.\nUpgrade to libgnutls11-dev_1.0.16-13.2\n');
}
if (deb_check(prefix: 'gnutls11', release: '3.1', reference: '1.0.16-13.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnutls11 is vulnerable in Debian sarge.\nUpgrade to gnutls11_1.0.16-13.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
