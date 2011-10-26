# This script was automatically generated from the dsa-310
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
XaoS, a program for displaying fractal images, is installed setuid
root on certain architectures in order to use svgalib, which requires
access to the video hardware.  However, it is not designed for secure
setuid execution, and can be exploited to gain root privileges.
In these updated packages, the setuid bit has been removed from the
xaos binary.  Users who require the svgalib functionality should grant
these privileges only to a trusted group.
This vulnerability is exploitable in version 3.0-18 (potato) on i386
and alpha architectures, and in version 3.0-23 (woody) on the i386
architecture only.
For the stable distribution (woody) this problem has been fixed in
version 3.0-23woody1.
For the old stable distribution (potato) this problem has been fixed
in version 3.0-18potato1.
For the unstable distribution (sid) this problem has been fixed in
version 3.1r-4.
We recommend that you update your xaos package.


Solution : http://www.debian.org/security/2003/dsa-310
Risk factor : High';

if (description) {
 script_id(15147);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "310");
 script_cve_id("CVE-2003-0385");
 script_bugtraq_id(7838);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA310] DSA-310-1 xaos");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-310-1 xaos");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xaos', release: '2.2', reference: '3.0-18potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaos is vulnerable in Debian 2.2.\nUpgrade to xaos_3.0-18potato1\n');
}
if (deb_check(prefix: 'xaos', release: '3.0', reference: '3.0-23woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaos is vulnerable in Debian 3.0.\nUpgrade to xaos_3.0-23woody1\n');
}
if (deb_check(prefix: 'xaos', release: '3.1', reference: '3.1r-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaos is vulnerable in Debian 3.1.\nUpgrade to xaos_3.1r-4\n');
}
if (deb_check(prefix: 'xaos', release: '2.2', reference: '3.0-18potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaos is vulnerable in Debian potato.\nUpgrade to xaos_3.0-18potato1\n');
}
if (deb_check(prefix: 'xaos', release: '3.0', reference: '3.0-23woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xaos is vulnerable in Debian woody.\nUpgrade to xaos_3.0-23woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
