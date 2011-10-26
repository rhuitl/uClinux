# This script was automatically generated from the dsa-671
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Max Vozeler discovered several format string vulnerabilities in the
movemail utility of Emacs, the well-known editor.  Via connecting to a
malicious POP server an attacker can execute arbitrary code under the
privileges of group mail.
For the stable distribution (woody) these problems have been fixed in
version 21.4.6-8woody2.
For the unstable distribution (sid) these problems have been fixed in
version 21.4.16-2.
We recommend that you upgrade your emacs packages.


Solution : http://www.debian.org/security/2005/dsa-671
Risk factor : High';

if (description) {
 script_id(16345);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "671");
 script_cve_id("CVE-2005-0100");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA671] DSA-671-1 xemacs21");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-671-1 xemacs21");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xemacs21', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21 is vulnerable in Debian 3.0.\nUpgrade to xemacs21_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-bin', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-bin is vulnerable in Debian 3.0.\nUpgrade to xemacs21-bin_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-gnome-mule', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-gnome-mule is vulnerable in Debian 3.0.\nUpgrade to xemacs21-gnome-mule_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-gnome-mule-canna-wnn', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-gnome-mule-canna-wnn is vulnerable in Debian 3.0.\nUpgrade to xemacs21-gnome-mule-canna-wnn_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-gnome-nomule', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-gnome-nomule is vulnerable in Debian 3.0.\nUpgrade to xemacs21-gnome-nomule_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-mule', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-mule is vulnerable in Debian 3.0.\nUpgrade to xemacs21-mule_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-mule-canna-wnn', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-mule-canna-wnn is vulnerable in Debian 3.0.\nUpgrade to xemacs21-mule-canna-wnn_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-nomule', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-nomule is vulnerable in Debian 3.0.\nUpgrade to xemacs21-nomule_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-support', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-support is vulnerable in Debian 3.0.\nUpgrade to xemacs21-support_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21-supportel', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21-supportel is vulnerable in Debian 3.0.\nUpgrade to xemacs21-supportel_21.4.6-8woody2\n');
}
if (deb_check(prefix: 'xemacs21', release: '3.1', reference: '21.4.16-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21 is vulnerable in Debian 3.1.\nUpgrade to xemacs21_21.4.16-2\n');
}
if (deb_check(prefix: 'xemacs21', release: '3.0', reference: '21.4.6-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xemacs21 is vulnerable in Debian woody.\nUpgrade to xemacs21_21.4.6-8woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
