# This script was automatically generated from the dsa-676
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered a buffer overflow in pcdsvgaview, an SVGA
PhotoCD viewer.  xpcd-svga is part of xpcd and uses svgalib to display
graphics on the Linux console for which root permissions are required.
A malicious user could overflow a fixed-size buffer and may cause the
program to execute arbitrary code with elevated privileges.
For the stable distribution (woody) this problem has been fixed in
version 2.08-8woody3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your xpcd-svga package immediately.


Solution : http://www.debian.org/security/2005/dsa-676
Risk factor : High';

if (description) {
 script_id(16380);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "676");
 script_cve_id("CVE-2005-0074");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA676] DSA-676-1 xpcd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-676-1 xpcd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpcd', release: '3.0', reference: '2.08-8woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd is vulnerable in Debian 3.0.\nUpgrade to xpcd_2.08-8woody3\n');
}
if (deb_check(prefix: 'xpcd-gimp', release: '3.0', reference: '2.08-8woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd-gimp is vulnerable in Debian 3.0.\nUpgrade to xpcd-gimp_2.08-8woody3\n');
}
if (deb_check(prefix: 'xpcd-svga', release: '3.0', reference: '2.08-8woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd-svga is vulnerable in Debian 3.0.\nUpgrade to xpcd-svga_2.08-8woody3\n');
}
if (deb_check(prefix: 'xpcd', release: '3.0', reference: '2.08-8woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd is vulnerable in Debian woody.\nUpgrade to xpcd_2.08-8woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
