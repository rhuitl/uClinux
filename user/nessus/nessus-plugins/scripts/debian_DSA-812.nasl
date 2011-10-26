# This script was automatically generated from the dsa-812
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Peter Karlsson discovered a buffer overflow in Turquoise SuperStat, a
program for gathering statistics from Fidonet and Usenet, that can be
exploited by a specially crafted NNTP server.
For the old stable distribution (woody) this problem has been fixed in
version 2.2.1woody1.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.2.4-1.
We recommend that you upgrade your turqstat package.


Solution : http://www.debian.org/security/2005/dsa-812
Risk factor : High';

if (description) {
 script_id(19708);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "812");
 script_cve_id("CVE-2005-2658");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA812] DSA-812-1 turqstat");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-812-1 turqstat");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'turqstat', release: '', reference: '2.2.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package turqstat is vulnerable in Debian .\nUpgrade to turqstat_2.2.4-1\n');
}
if (deb_check(prefix: 'turqstat', release: '3.0', reference: '2.2.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package turqstat is vulnerable in Debian 3.0.\nUpgrade to turqstat_2.2.1woody1\n');
}
if (deb_check(prefix: 'xturqstat', release: '3.0', reference: '2.2.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xturqstat is vulnerable in Debian 3.0.\nUpgrade to xturqstat_2.2.1woody1\n');
}
if (deb_check(prefix: 'turqstat', release: '3.1', reference: '2.2.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package turqstat is vulnerable in Debian 3.1.\nUpgrade to turqstat_2.2.2sarge1\n');
}
if (deb_check(prefix: 'xturqstat', release: '3.1', reference: '2.2.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xturqstat is vulnerable in Debian 3.1.\nUpgrade to xturqstat_2.2.2sarge1\n');
}
if (deb_check(prefix: 'turqstat', release: '3.1', reference: '2.2.2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package turqstat is vulnerable in Debian sarge.\nUpgrade to turqstat_2.2.2sarge1\n');
}
if (deb_check(prefix: 'turqstat', release: '3.0', reference: '2.2.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package turqstat is vulnerable in Debian woody.\nUpgrade to turqstat_2.2.1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
