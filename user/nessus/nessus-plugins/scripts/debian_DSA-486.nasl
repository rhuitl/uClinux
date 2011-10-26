# This script was automatically generated from the dsa-486
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered and fixed in CVS:
 Sebastian Krahmer discovered a vulnerability whereby
 a malicious CVS pserver could create arbitrary files on the client
 system during an update or checkout operation, by supplying absolute
 pathnames in RCS diffs.
 Derek Robert Price discovered a vulnerability whereby
 a CVS pserver could be abused by a malicious client to view the
 contents of certain files outside of the CVS root directory using
 relative pathnames containing "../".
For the current stable distribution (woody) these problems have been
fixed in version 1.11.1p1debian-9woody2.
For the unstable distribution (sid), these problems will be fixed soon.
We recommend that you update your cvs package.


Solution : http://www.debian.org/security/2004/dsa-486
Risk factor : High';

if (description) {
 script_id(15323);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "486");
 script_cve_id("CVE-2004-0180", "CVE-2004-0405");
 script_bugtraq_id(10138, 10140);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA486] DSA-486-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-486-1 cvs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-9woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 3.0.\nUpgrade to cvs_1.11.1p1debian-9woody2\n');
}
if (deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-9woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian woody.\nUpgrade to cvs_1.11.1p1debian-9woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
