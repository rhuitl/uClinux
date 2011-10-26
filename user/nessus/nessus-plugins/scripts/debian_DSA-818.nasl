# This script was automatically generated from the dsa-818
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña discovered that langen2kvhtml from the
kvoctrain package from the kdeedu suite creates temporary files in an
insecure fashion.  This leaves them open for symlink attacks.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 3.3.2-3.sarge.1.
For the unstable distribution (sid) these problems have been fixed in
version 3.4.2-1.
We recommend that you upgrade your kvoctrain package.


Solution : http://www.debian.org/security/2005/dsa-818
Risk factor : High';

if (description) {
 script_id(19787);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "818");
 script_cve_id("CVE-2005-2101");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA818] DSA-818-1 kdeedu");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-818-1 kdeedu");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kdeedu', release: '', reference: '3.4.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdeedu is vulnerable in Debian .\nUpgrade to kdeedu_3.4.2-1\n');
}
if (deb_check(prefix: 'kalzium', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kalzium is vulnerable in Debian 3.1.\nUpgrade to kalzium_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kbruch', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kbruch is vulnerable in Debian 3.1.\nUpgrade to kbruch_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kdeedu', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdeedu is vulnerable in Debian 3.1.\nUpgrade to kdeedu_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kdeedu-data', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdeedu-data is vulnerable in Debian 3.1.\nUpgrade to kdeedu-data_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kdeedu-doc-html', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdeedu-doc-html is vulnerable in Debian 3.1.\nUpgrade to kdeedu-doc-html_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'keduca', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package keduca is vulnerable in Debian 3.1.\nUpgrade to keduca_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'khangman', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package khangman is vulnerable in Debian 3.1.\nUpgrade to khangman_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kig', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kig is vulnerable in Debian 3.1.\nUpgrade to kig_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kiten', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kiten is vulnerable in Debian 3.1.\nUpgrade to kiten_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'klatin', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klatin is vulnerable in Debian 3.1.\nUpgrade to klatin_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'klettres', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klettres is vulnerable in Debian 3.1.\nUpgrade to klettres_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'klettres-data', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package klettres-data is vulnerable in Debian 3.1.\nUpgrade to klettres-data_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kmessedwords', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmessedwords is vulnerable in Debian 3.1.\nUpgrade to kmessedwords_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kmplot', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kmplot is vulnerable in Debian 3.1.\nUpgrade to kmplot_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kpercentage', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kpercentage is vulnerable in Debian 3.1.\nUpgrade to kpercentage_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kstars', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kstars is vulnerable in Debian 3.1.\nUpgrade to kstars_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kstars-data', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kstars-data is vulnerable in Debian 3.1.\nUpgrade to kstars-data_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'ktouch', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ktouch is vulnerable in Debian 3.1.\nUpgrade to ktouch_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kturtle', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kturtle is vulnerable in Debian 3.1.\nUpgrade to kturtle_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kverbos', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kverbos is vulnerable in Debian 3.1.\nUpgrade to kverbos_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kvoctrain', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kvoctrain is vulnerable in Debian 3.1.\nUpgrade to kvoctrain_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kwordquiz', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kwordquiz is vulnerable in Debian 3.1.\nUpgrade to kwordquiz_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'libkdeedu-dev', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkdeedu-dev is vulnerable in Debian 3.1.\nUpgrade to libkdeedu-dev_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'libkdeedu1', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkdeedu1 is vulnerable in Debian 3.1.\nUpgrade to libkdeedu1_3.3.2-3.sarge.1\n');
}
if (deb_check(prefix: 'kdeedu', release: '3.1', reference: '3.3.2-3.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kdeedu is vulnerable in Debian sarge.\nUpgrade to kdeedu_3.3.2-3.sarge.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
