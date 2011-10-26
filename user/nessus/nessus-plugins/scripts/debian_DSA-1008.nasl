# This script was automatically generated from the dsa-1008
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcelo Ricardo Leitner noticed that the current patch in DSA 932
(CVE-2005-3627) for kpdf, the PDF viewer for KDE, does not fix all
buffer overflows, still allowing an attacker to execute arbitrary
code.
The old stable distribution (woody) does not contain kpdf packages.
For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-2sarge4.
The unstable distribution (sid) is not affected by this problem.
We recommend that you upgrade your kpdf package.


Solution : http://www.debian.org/security/2006/dsa-1008
Risk factor : High';

if (description) {
 script_id(22550);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1008");
 script_cve_id("CVE-2006-0746");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1008] DSA-1008-1 kdegraphics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1008-1 kdegraphics");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kamera', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kamera is vulnerable in Debian 3.1.\nUpgrade to kamera_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kcoloredit', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kcoloredit is vulnerable in Debian 3.1.\nUpgrade to kcoloredit_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kdegraphics', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdegraphics is vulnerable in Debian 3.1.\nUpgrade to kdegraphics_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kdegraphics-dev', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdegraphics-dev is vulnerable in Debian 3.1.\nUpgrade to kdegraphics-dev_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kdegraphics-kfile-plugins', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdegraphics-kfile-plugins is vulnerable in Debian 3.1.\nUpgrade to kdegraphics-kfile-plugins_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kdvi', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdvi is vulnerable in Debian 3.1.\nUpgrade to kdvi_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kfax', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kfax is vulnerable in Debian 3.1.\nUpgrade to kfax_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kgamma', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kgamma is vulnerable in Debian 3.1.\nUpgrade to kgamma_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kghostview', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kghostview is vulnerable in Debian 3.1.\nUpgrade to kghostview_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kiconedit', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kiconedit is vulnerable in Debian 3.1.\nUpgrade to kiconedit_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kmrml', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmrml is vulnerable in Debian 3.1.\nUpgrade to kmrml_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kolourpaint', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kolourpaint is vulnerable in Debian 3.1.\nUpgrade to kolourpaint_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kooka', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kooka is vulnerable in Debian 3.1.\nUpgrade to kooka_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kpdf', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpdf is vulnerable in Debian 3.1.\nUpgrade to kpdf_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kpovmodeler', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpovmodeler is vulnerable in Debian 3.1.\nUpgrade to kpovmodeler_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kruler', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kruler is vulnerable in Debian 3.1.\nUpgrade to kruler_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'ksnapshot', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksnapshot is vulnerable in Debian 3.1.\nUpgrade to ksnapshot_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'ksvg', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksvg is vulnerable in Debian 3.1.\nUpgrade to ksvg_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kuickshow', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kuickshow is vulnerable in Debian 3.1.\nUpgrade to kuickshow_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kview', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kview is vulnerable in Debian 3.1.\nUpgrade to kview_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kviewshell', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kviewshell is vulnerable in Debian 3.1.\nUpgrade to kviewshell_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'libkscan-dev', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkscan-dev is vulnerable in Debian 3.1.\nUpgrade to libkscan-dev_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'libkscan1', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkscan1 is vulnerable in Debian 3.1.\nUpgrade to libkscan1_3.3.2-2sarge4\n');
}
if (deb_check(prefix: 'kdegraphics', release: '3.1', reference: '3.3.2-2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdegraphics is vulnerable in Debian sarge.\nUpgrade to kdegraphics_3.3.2-2sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
