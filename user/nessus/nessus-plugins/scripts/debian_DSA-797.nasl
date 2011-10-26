# This script was automatically generated from the dsa-797
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
zsync, a file transfer program, includes a modified local copy of
the zlib library, and is vulnerable to certain bugs fixed previously
in the zlib package.
There was a build error for the sarge i386 proftpd packages released in
DSA 797-1. A new build, zsync_0.3.3-1.sarge.1.2, has been prepared to
correct this error. The packages for other architectures are unaffected.
The old stable distribution (woody) does not contain the zsync
package.
For the stable distribution (sarge) this problem has been fixed in
version 0.3.3-1.sarge.1.
For the unstable distribution (sid) this problem has been fixed in
version 0.4.0-2.
We recommend that you upgrade your zsync package.


Solution : http://www.debian.org/security/2005/dsa-797
Risk factor : High';

if (description) {
 script_id(19567);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "797");
 script_cve_id("CVE-2005-1849", "CVE-2005-2096");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA797] DSA-797-2 zsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-797-2 zsync");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zsync', release: '', reference: '0.4.0-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zsync is vulnerable in Debian .\nUpgrade to zsync_0.4.0-2\n');
}
if (deb_check(prefix: 'zsync', release: '3.1', reference: '0.3.3-1.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zsync is vulnerable in Debian 3.1.\nUpgrade to zsync_0.3.3-1.sarge.1\n');
}
if (deb_check(prefix: 'zsync', release: '3.1', reference: '0.3.3-1.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zsync is vulnerable in Debian sarge.\nUpgrade to zsync_0.3.3-1.sarge.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
