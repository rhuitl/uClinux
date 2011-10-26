# This script was automatically generated from the dsa-1195
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Multiple vulnerabilities have been discovered in the OpenSSL
cryptographic software package that could allow an attacker to launch
a denial of service attack by exhausting system resources or crashing
processes on a victim\'s computer.
        Tavis Ormandy and Will Drewry of the Google Security Team
        discovered a buffer overflow in SSL_get_shared_ciphers utility
        function, used by some applications such as exim and mysql.  An
        attacker could send a list of ciphers that would overrun a
        buffer.
        Tavis Ormandy and Will Drewry of the Google Security Team
        discovered a possible DoS in the sslv2 client code.  Where a
        client application uses OpenSSL to make a SSLv2 connection to
        a malicious server that server could cause the client to
        crash.
        Dr S N Henson of the OpenSSL core team and Open Network
        Security recently developed an ASN1 test suite for NISCC
        (www.niscc.gov.uk). When the test suite was run against
        OpenSSL a DoS was discovered.
        Certain types of public key can take disproportionate amounts
        of time to process. This could be used by an attacker in a
        denial of service attack.
For the stable distribution (sarge) these problems have been fixed in
version 0.9.6m-1sarge4.
This package exists only for compatibility with older software, and is
not present in the unstable or testing branches of Debian.
We recommend that you upgrade your openssl096 package.  Note that
services linking against the openssl shared libraries will need to be
restarted. Common examples of such services include most Mail
Transport Agents, SSH servers, and web servers.


Solution : http://www.debian.org/security/2006/dsa-1195
Risk factor : High';

if (description) {
 script_id(22881);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1195");
 script_cve_id("CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1195] DSA-1195-1 openssl096");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1195-1 openssl096");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl0.9.6', release: '3.1', reference: '0.9.6m-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.6 is vulnerable in Debian 3.1.\nUpgrade to libssl0.9.6_0.9.6m-1sarge4\n');
}
if (deb_check(prefix: 'openssl096', release: '3.1', reference: '0.9.6m-1sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl096 is vulnerable in Debian sarge.\nUpgrade to openssl096_0.9.6m-1sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
