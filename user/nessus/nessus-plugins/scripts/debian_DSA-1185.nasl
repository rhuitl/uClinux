# This script was automatically generated from the dsa-1185
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The fix used to correct CVE-2006-2940 introduced code that could lead to
the use of uninitialized memory.  Such use is likely to cause the
application using the openssl library to crash, and has the potential to
allow an attacker to cause the execution of arbitrary code.
For reference please find below the original advisory text:
Multiple vulnerabilities have been discovered in the OpenSSL
cryptographic software package that could allow an attacker to launch
a denial of service attack by exhausting system resources or crashing
processes on a victim\'s computer.
	Dr S N Henson of the OpenSSL core team and Open Network
	Security recently developed an ASN1 test suite for NISCC
	(www.niscc.gov.uk). When the test suite was run against
	OpenSSL two denial of service vulnerabilities were discovered.
	During the parsing of certain invalid ASN1 structures an error
	condition is mishandled. This can result in an infinite loop
	which consumes system memory.
	Any code which uses OpenSSL to parse ASN1 data from untrusted
	sources is affected. This includes SSL servers which enable
	client authentication and S/MIME applications.
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
version 0.9.7e-3sarge4.
For the unstable and testing distributions (sid and etch,
respectively), these problems will be fixed in version 0.9.7k-3 of the
openssl097 compatibility libraries, and version 0.9.8c-3 of the
openssl package.
We recommend that you upgrade your openssl package.  Note that
services linking against the openssl shared libraries will need to be
restarted. Common examples of such services include most Mail
Transport Agents, SSH servers, and web servers.


Solution : http://www.debian.org/security/2006/dsa-1185
Risk factor : High';

if (description) {
 script_id(22727);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1185");
 script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1185] DSA-1185-2 openssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1185-2 openssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl-dev', release: '3.1', reference: '0.9.7e-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl-dev is vulnerable in Debian 3.1.\nUpgrade to libssl-dev_0.9.7e-3sarge4\n');
}
if (deb_check(prefix: 'libssl0.9.7', release: '3.1', reference: '0.9.7e-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl0.9.7 is vulnerable in Debian 3.1.\nUpgrade to libssl0.9.7_0.9.7e-3sarge4\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian 3.1.\nUpgrade to openssl_0.9\n');
}
if (deb_check(prefix: 'openssl', release: '3.1', reference: '0.9.7e-3sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl is vulnerable in Debian sarge.\nUpgrade to openssl_0.9.7e-3sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
