# This script was automatically generated from the dsa-284
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The KDE team discovered a vulnerability in the way KDE uses Ghostscript
software for processing of PostScript (PS) and PDF files.  An attacker
could provide a malicious PostScript or PDF file via mail or websites
that could lead to executing arbitrary commands under the privileges
of the user viewing the file or when the browser generates a directory
listing with thumbnails.
For the stable distribution (woody) this problem has been fixed in
version 2.2.2-6.11 of kdegraphics and associated packages.
The old stable distribution (potato) is not affected since it does not
contain KDE.
For the unstable distribution (sid) this problem will be fixed soon.
For the unofficial backport of KDE 3.1.1 to woody by Ralf Nolden on
download.kde.org, this problem has been fixed in version 3.1.1-0woody2
of kdegraphics.  Using the normal backport line for apt-get you will
get the update:
  deb http://download.kde.org/stable/latest/Debian stable main
We recommend that you upgrade your kdegraphics and associated packages.


Solution : http://www.debian.org/security/2003/dsa-284
Risk factor : High';

if (description) {
 script_id(15121);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "284");
 script_cve_id("CVE-2003-0204");
 script_bugtraq_id(7318);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA284] DSA-284-1 kdegraphics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-284-1 kdegraphics");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kamera', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kamera is vulnerable in Debian 3.0.\nUpgrade to kamera_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kcoloredit', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kcoloredit is vulnerable in Debian 3.0.\nUpgrade to kcoloredit_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kfract', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kfract is vulnerable in Debian 3.0.\nUpgrade to kfract_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kghostview', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kghostview is vulnerable in Debian 3.0.\nUpgrade to kghostview_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kiconedit', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kiconedit is vulnerable in Debian 3.0.\nUpgrade to kiconedit_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kooka', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kooka is vulnerable in Debian 3.0.\nUpgrade to kooka_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kpaint', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpaint is vulnerable in Debian 3.0.\nUpgrade to kpaint_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kruler', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kruler is vulnerable in Debian 3.0.\nUpgrade to kruler_2.2.2-6.11\n');
}
if (deb_check(prefix: 'ksnapshot', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksnapshot is vulnerable in Debian 3.0.\nUpgrade to ksnapshot_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kview', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kview is vulnerable in Debian 3.0.\nUpgrade to kview_2.2.2-6.11\n');
}
if (deb_check(prefix: 'libkscan-dev', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkscan-dev is vulnerable in Debian 3.0.\nUpgrade to libkscan-dev_2.2.2-6.11\n');
}
if (deb_check(prefix: 'libkscan1', release: '3.0', reference: '2.2.2-6.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkscan1 is vulnerable in Debian 3.0.\nUpgrade to libkscan1_2.2.2-6.11\n');
}
if (deb_check(prefix: 'kdegraphics', release: '3.0', reference: '2.2.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdegraphics is vulnerable in Debian woody.\nUpgrade to kdegraphics_2.2.2-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
