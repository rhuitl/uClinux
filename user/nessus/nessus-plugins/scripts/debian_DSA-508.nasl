# This script was automatically generated from the dsa-508
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jaguar discovered a vulnerability in one component of xpcd, a PhotoCD
viewer.  xpcd-svga, part of xpcd which uses svgalib to display
graphics on the console, would copy user-supplied data of arbitrary
length into a fixed-size buffer in the pcd_open function.
For the current stable distribution (woody) this problem has been
fixed in version 2.08-8woody2.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your xpcd package.


Solution : http://www.debian.org/security/2004/dsa-508
Risk factor : High';

if (description) {
 script_id(15345);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "508");
 script_cve_id("CVE-2004-0402");
 script_bugtraq_id(10403);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA508] DSA-508-1 xpcd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-508-1 xpcd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpcd', release: '3.0', reference: '2.08-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd is vulnerable in Debian 3.0.\nUpgrade to xpcd_2.08-8woody1\n');
}
if (deb_check(prefix: 'xpcd-gimp', release: '3.0', reference: '2.08-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd-gimp is vulnerable in Debian 3.0.\nUpgrade to xpcd-gimp_2.08-8woody1\n');
}
if (deb_check(prefix: 'xpcd-svga', release: '3.0', reference: '2.08-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd-svga is vulnerable in Debian 3.0.\nUpgrade to xpcd-svga_2.08-8woody1\n');
}
if (deb_check(prefix: 'xpcd', release: '3.0', reference: '2.08-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd is vulnerable in Debian woody.\nUpgrade to xpcd_2.08-8woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
