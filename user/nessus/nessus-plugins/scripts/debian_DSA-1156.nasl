# This script was automatically generated from the dsa-1156
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ludwig Nussel discovered that kdm, the X display manager for KDE, handles
access to the session type configuration file insecurely, which may lead
to the disclosure of arbitrary files through a symlink attack.
For the stable distribution (sarge) this problem has been fixed in
version 3.3.2-1sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 3.5.2-2.
We recommend that you upgrade your kdm package.


Solution : http://www.debian.org/security/2006/dsa-1156
Risk factor : High';

if (description) {
 script_id(22698);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1156");
 script_cve_id("CVE-2006-2449");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1156] DSA-1156-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1156-1 kdebase");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdebase', release: '', reference: '3.5.2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian .\nUpgrade to kdebase_3.5.2-2\n');
}
if (deb_check(prefix: 'kappfinder', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kappfinder is vulnerable in Debian 3.1.\nUpgrade to kappfinder_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kate', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kate is vulnerable in Debian 3.1.\nUpgrade to kate_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kcontrol', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kcontrol is vulnerable in Debian 3.1.\nUpgrade to kcontrol_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdebase', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian 3.1.\nUpgrade to kdebase_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdebase-bin', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-bin is vulnerable in Debian 3.1.\nUpgrade to kdebase-bin_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdebase-data', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-data is vulnerable in Debian 3.1.\nUpgrade to kdebase-data_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdebase-dev', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-dev is vulnerable in Debian 3.1.\nUpgrade to kdebase-dev_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdebase-doc', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-doc is vulnerable in Debian 3.1.\nUpgrade to kdebase-doc_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdebase-kio-plugins', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase-kio-plugins is vulnerable in Debian 3.1.\nUpgrade to kdebase-kio-plugins_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdepasswd', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdepasswd is vulnerable in Debian 3.1.\nUpgrade to kdepasswd_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdeprint', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdeprint is vulnerable in Debian 3.1.\nUpgrade to kdeprint_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdesktop', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdesktop is vulnerable in Debian 3.1.\nUpgrade to kdesktop_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdm', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdm is vulnerable in Debian 3.1.\nUpgrade to kdm_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kfind', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kfind is vulnerable in Debian 3.1.\nUpgrade to kfind_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'khelpcenter', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package khelpcenter is vulnerable in Debian 3.1.\nUpgrade to khelpcenter_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kicker', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kicker is vulnerable in Debian 3.1.\nUpgrade to kicker_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'klipper', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klipper is vulnerable in Debian 3.1.\nUpgrade to klipper_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kmenuedit', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmenuedit is vulnerable in Debian 3.1.\nUpgrade to kmenuedit_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'konqueror', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konqueror is vulnerable in Debian 3.1.\nUpgrade to konqueror_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'konqueror-nsplugins', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konqueror-nsplugins is vulnerable in Debian 3.1.\nUpgrade to konqueror-nsplugins_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'konsole', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package konsole is vulnerable in Debian 3.1.\nUpgrade to konsole_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kpager', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpager is vulnerable in Debian 3.1.\nUpgrade to kpager_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kpersonalizer', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpersonalizer is vulnerable in Debian 3.1.\nUpgrade to kpersonalizer_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'ksmserver', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksmserver is vulnerable in Debian 3.1.\nUpgrade to ksmserver_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'ksplash', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksplash is vulnerable in Debian 3.1.\nUpgrade to ksplash_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'ksysguard', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksysguard is vulnerable in Debian 3.1.\nUpgrade to ksysguard_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'ksysguardd', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ksysguardd is vulnerable in Debian 3.1.\nUpgrade to ksysguardd_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'ktip', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ktip is vulnerable in Debian 3.1.\nUpgrade to ktip_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kwin', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kwin is vulnerable in Debian 3.1.\nUpgrade to kwin_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'libkonq4', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkonq4 is vulnerable in Debian 3.1.\nUpgrade to libkonq4_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'libkonq4-dev', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkonq4-dev is vulnerable in Debian 3.1.\nUpgrade to libkonq4-dev_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'xfonts-konsole', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xfonts-konsole is vulnerable in Debian 3.1.\nUpgrade to xfonts-konsole_3.3.2-1sarge3\n');
}
if (deb_check(prefix: 'kdebase', release: '3.1', reference: '3.3.2-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdebase is vulnerable in Debian sarge.\nUpgrade to kdebase_3.3.2-1sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
