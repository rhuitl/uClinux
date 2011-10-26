# This script was automatically generated from the dsa-628
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Pavel Kankovsky discovered that several overflows found in the libXpm
library were also present in imlib and imlib2, imaging libraries for
X11.  An attacker could create a carefully crafted image file in such
a way that it could cause an application linked with imlib or imlib2
to execute arbitrary code when the file was opened by a victim.  The
Common Vulnerabilities and Exposures project identifies the following
problems:
    Multiple heap-based buffer overflows.  No such code is present in
    imlib2.
    Multiple integer overflows in the imlib library.
For the stable distribution (woody) these problems have been fixed in
version 1.0.5-2woody2.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your imlib2 packages.


Solution : http://www.debian.org/security/2005/dsa-628
Risk factor : High';

if (description) {
 script_id(16106);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "628");
 script_cve_id("CVE-2004-1025", "CVE-2004-1026");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA628] DSA-628-1 imlib2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-628-1 imlib2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libimlib2', release: '3.0', reference: '1.0.5-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libimlib2 is vulnerable in Debian 3.0.\nUpgrade to libimlib2_1.0.5-2woody2\n');
}
if (deb_check(prefix: 'libimlib2-dev', release: '3.0', reference: '1.0.5-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libimlib2-dev is vulnerable in Debian 3.0.\nUpgrade to libimlib2-dev_1.0.5-2woody2\n');
}
if (deb_check(prefix: 'imlib2', release: '3.0', reference: '1.0.5-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imlib2 is vulnerable in Debian woody.\nUpgrade to imlib2_1.0.5-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
