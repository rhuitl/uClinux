# This script was automatically generated from the dsa-296
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
version 2.2.2-14.4 of kdebase and associated packages.
The old stable distribution (potato) is not affected since it does not
contain KDE.
For the unstable distribution (sid) this problem will be fixed soon.
For the unofficial backport of KDE 3.1.1 to woody by Ralf Nolden on
download.kde.org, this problem has been fixed in version 3.1.1-0woody3
of kdebase.  Using the normal backport line for apt-get you will get
the update:
  deb http://download.kde.org/stable/latest/Debian stable main
We recommend that you upgrade your kdebase and associated packages.


Solution : http://www.debian.org/security/2003/dsa-296
Risk factor : High';

if (description) {
 script_id(15133);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "296");
 script_cve_id("CVE-2003-0204");
 script_bugtraq_id(7318);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA296] DSA-296-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-296-1 kdebase");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kate', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kate is vulnerable in Debian 3.0.\nUpgrade to kate_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian 3.0.\nUpgrade to kdebase_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kdebase-audiolibs', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-audiolibs is vulnerable in Debian 3.0.\nUpgrade to kdebase-audiolibs_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kdebase-dev', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-dev is vulnerable in Debian 3.0.\nUpgrade to kdebase-dev_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kdebase-doc', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-doc is vulnerable in Debian 3.0.\nUpgrade to kdebase-doc_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kdebase-libs', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-libs is vulnerable in Debian 3.0.\nUpgrade to kdebase-libs_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kdewallpapers', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdewallpapers is vulnerable in Debian 3.0.\nUpgrade to kdewallpapers_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kdm', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdm is vulnerable in Debian 3.0.\nUpgrade to kdm_2.2.2-14.4\n');
}
if (deb_check(prefix: 'konqueror', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konqueror is vulnerable in Debian 3.0.\nUpgrade to konqueror_2.2.2-14.4\n');
}
if (deb_check(prefix: 'konsole', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konsole is vulnerable in Debian 3.0.\nUpgrade to konsole_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kscreensaver', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kscreensaver is vulnerable in Debian 3.0.\nUpgrade to kscreensaver_2.2.2-14.4\n');
}
if (deb_check(prefix: 'libkonq-dev', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkonq-dev is vulnerable in Debian 3.0.\nUpgrade to libkonq-dev_2.2.2-14.4\n');
}
if (deb_check(prefix: 'libkonq3', release: '3.0', reference: '2.2.2-14.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkonq3 is vulnerable in Debian 3.0.\nUpgrade to libkonq3_2.2.2-14.4\n');
}
if (deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian woody.\nUpgrade to kdebase_2.2.2-14\n');
}
if (w) { security_hole(port: 0, data: desc); }
