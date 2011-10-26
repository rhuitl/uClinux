# This script was automatically generated from the dsa-182
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Zen-parse discovered a buffer overflow in gv, a PostScript and PDF
viewer for X11.  The same code is present in kghostview which is part
of the KDE-Graphics package.  This problem is triggered by scanning
the PostScript file and can be exploited by an attacker sending a
malformed PostScript or PDF file.  The attacker is able to cause
arbitrary code to be run with the privileges of the victim.
This problem has been fixed in version 2.2.2-6.8 for the current
stable distribution (woody) and in version 2.2.2-6.9 for the unstable
distribution (sid).  The old stable distribution (potato) is not
affected since no KDE is included.
We recommend that you upgrade your kghostview package.


Solution : http://www.debian.org/security/2002/dsa-182
Risk factor : High';

if (description) {
 script_id(15019);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "182");
 script_cve_id("CVE-2002-0838");
 script_bugtraq_id(5808);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA182] DSA-182-1 kdegraphics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-182-1 kdegraphics");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kamera', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kamera is vulnerable in Debian 3.0.\nUpgrade to kamera_2.2.2-6.8\n');
}
if (deb_check(prefix: 'kcoloredit', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kcoloredit is vulnerable in Debian 3.0.\nUpgrade to kcoloredit_2.2.2-6.8\n');
}
if (deb_check(prefix: 'kfract', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kfract is vulnerable in Debian 3.0.\nUpgrade to kfract_2.2.2-6.8\n');
}
if (deb_check(prefix: 'kghostview', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kghostview is vulnerable in Debian 3.0.\nUpgrade to kghostview_2.2.2-6.8\n');
}
if (deb_check(prefix: 'kiconedit', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kiconedit is vulnerable in Debian 3.0.\nUpgrade to kiconedit_2.2.2-6.8\n');
}
if (deb_check(prefix: 'kooka', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kooka is vulnerable in Debian 3.0.\nUpgrade to kooka_2.2.2-6.8\n');
}
if (deb_check(prefix: 'kpaint', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpaint is vulnerable in Debian 3.0.\nUpgrade to kpaint_2.2.2-6.8\n');
}
if (deb_check(prefix: 'kruler', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kruler is vulnerable in Debian 3.0.\nUpgrade to kruler_2.2.2-6.8\n');
}
if (deb_check(prefix: 'ksnapshot', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksnapshot is vulnerable in Debian 3.0.\nUpgrade to ksnapshot_2.2.2-6.8\n');
}
if (deb_check(prefix: 'kview', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kview is vulnerable in Debian 3.0.\nUpgrade to kview_2.2.2-6.8\n');
}
if (deb_check(prefix: 'libkscan-dev', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkscan-dev is vulnerable in Debian 3.0.\nUpgrade to libkscan-dev_2.2.2-6.8\n');
}
if (deb_check(prefix: 'libkscan1', release: '3.0', reference: '2.2.2-6.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkscan1 is vulnerable in Debian 3.0.\nUpgrade to libkscan1_2.2.2-6.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
