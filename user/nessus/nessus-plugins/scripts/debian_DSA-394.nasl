# This script was automatically generated from the dsa-394
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Henson of the OpenSSL core team identified and prepared fixes
for a number of vulnerabilities in the OpenSSL ASN1 code that were
discovered after running a test suite by British National
Infrastructure Security Coordination Centre (NISCC).
A bug in OpenSSLs SSL/TLS protocol was also identified which causes
OpenSSL to parse a client certificate from an SSL/TLS client when it
should reject it as a protocol error.
The Common Vulnerabilities and Exposures project identifies the
following problems:
Integer overflow in OpenSSL that allows remote attackers to cause a
   denial of service (crash) via an SSL client certificate with
   certain ASN.1 tag values.
OpenSSL does not properly track the number of characters in certain
   ASN.1 inputs, which allows remote attackers to cause a denial of
   service (crash) via an SSL client certificate that causes OpenSSL
   to read past the end of a buffer when the long form is used.
Double-free vulnerability allows remote attackers to cause a denial
   of service (crash) and possibly execute arbitrary code via an SSL
   client certificate with a certain invalid ASN.1 encoding.  This bug
   was only present in OpenSSL 0.9.7 and is listed here only for
   reference.
For the stable distribution (woody) this problem has been
fixed in openssl095 version 0.9.5a-6.woody.3.
This package is not present in the unstable (sid) or testing (sarge)
distribution.
We recommend that you upgrade your libssl095a packages and restart
services using this library.  Debian doesn\'t ship any packages that
are linked against this library.
The following commandline (courtesy of Ray Dassen) produces a list of
names of running processes that have libssl095 mapped into their
memory space:

    find /proc -name maps -exec egrep -l \'libssl095\' {} /dev/null \\;     | sed -e \'s/[^0-9]//g\' | xargs --no-run-if-empty ps --no-headers -p |     sed -e \'s/^\\+//\' -e \'s/ \\+/ /g\' | cut -d \' \' -f 5 | sort | uniq


You should restart the associated services.


Solution : http://www.debian.org/security/2003/dsa-394
Risk factor : High';

if (description) {
 script_id(15231);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "394");
 script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
 script_bugtraq_id(8732);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA394] DSA-394-1 openssl095");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-394-1 openssl095");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libssl095a', release: '3.0', reference: '0.9.5a-6.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libssl095a is vulnerable in Debian 3.0.\nUpgrade to libssl095a_0.9.5a-6.woody.3\n');
}
if (deb_check(prefix: 'openssl095', release: '3.0', reference: '0.9.5a-6.woody.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openssl095 is vulnerable in Debian woody.\nUpgrade to openssl095_0.9.5a-6.woody.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
