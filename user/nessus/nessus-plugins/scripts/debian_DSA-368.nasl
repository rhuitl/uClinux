# This script was automatically generated from the dsa-368
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a buffer overflow in xpcd-svga which can be
triggered by a long HOME environment variable.  This vulnerability
could be exploited by a local attacker to gain root privileges.
For the stable distribution (woody) this problem has been fixed in
version 2.08-8woody1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your xpcd package.


Solution : http://www.debian.org/security/2003/dsa-368
Risk factor : High';

if (description) {
 script_id(15205);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "368");
 script_cve_id("CVE-2003-0649");
 script_bugtraq_id(8370);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA368] DSA-368-1 xpcd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-368-1 xpcd");
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
if (deb_check(prefix: 'xpcd', release: '3.0', reference: '2.08-8woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpcd is vulnerable in Debian woody.\nUpgrade to xpcd_2.08-8woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
