# This script was automatically generated from the dsa-1004
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Simon Kilvington discovered that specially crafted PNG images can trigger
a heap overflow in libavcodec, the multimedia library of ffmpeg, which may
lead to the execution of arbitrary code.
The vlc media player links statically against libavcodec.
The old stable distribution (woody) isn\'t affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.8.1.svn20050314-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.8.4.debian-2.
We recommend that you upgrade your vlc package.


Solution : http://www.debian.org/security/2006/dsa-1004
Risk factor : High';

if (description) {
 script_id(22546);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1004");
 script_cve_id("CVE-2005-4048");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1004] DSA-1004-1 vlc");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1004-1 vlc");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'vlc', release: '', reference: '0.8.4.debian-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc is vulnerable in Debian .\nUpgrade to vlc_0.8.4.debian-2\n');
}
if (deb_check(prefix: 'gnome-vlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gnome-vlc is vulnerable in Debian 3.1.\nUpgrade to gnome-vlc_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'gvlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gvlc is vulnerable in Debian 3.1.\nUpgrade to gvlc_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'kvlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kvlc is vulnerable in Debian 3.1.\nUpgrade to kvlc_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'libvlc0-dev', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libvlc0-dev is vulnerable in Debian 3.1.\nUpgrade to libvlc0-dev_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'mozilla-plugin-vlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mozilla-plugin-vlc is vulnerable in Debian 3.1.\nUpgrade to mozilla-plugin-vlc_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'qvlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package qvlc is vulnerable in Debian 3.1.\nUpgrade to qvlc_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc is vulnerable in Debian 3.1.\nUpgrade to vlc_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-alsa', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-alsa is vulnerable in Debian 3.1.\nUpgrade to vlc-alsa_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-esd', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-esd is vulnerable in Debian 3.1.\nUpgrade to vlc-esd_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-ggi', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-ggi is vulnerable in Debian 3.1.\nUpgrade to vlc-ggi_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-glide', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-glide is vulnerable in Debian 3.1.\nUpgrade to vlc-glide_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-gnome', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-gnome is vulnerable in Debian 3.1.\nUpgrade to vlc-gnome_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-gtk', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-gtk is vulnerable in Debian 3.1.\nUpgrade to vlc-gtk_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-plugin-alsa', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-plugin-alsa is vulnerable in Debian 3.1.\nUpgrade to vlc-plugin-alsa_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-plugin-arts', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-plugin-arts is vulnerable in Debian 3.1.\nUpgrade to vlc-plugin-arts_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-plugin-esd', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-plugin-esd is vulnerable in Debian 3.1.\nUpgrade to vlc-plugin-esd_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-plugin-ggi', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-plugin-ggi is vulnerable in Debian 3.1.\nUpgrade to vlc-plugin-ggi_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-plugin-glide', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-plugin-glide is vulnerable in Debian 3.1.\nUpgrade to vlc-plugin-glide_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-plugin-sdl', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-plugin-sdl is vulnerable in Debian 3.1.\nUpgrade to vlc-plugin-sdl_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-plugin-svgalib', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-plugin-svgalib is vulnerable in Debian 3.1.\nUpgrade to vlc-plugin-svgalib_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-qt', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-qt is vulnerable in Debian 3.1.\nUpgrade to vlc-qt_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc-sdl', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc-sdl is vulnerable in Debian 3.1.\nUpgrade to vlc-sdl_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'wxvlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wxvlc is vulnerable in Debian 3.1.\nUpgrade to wxvlc_0.8.1.svn20050314-1sarge1\n');
}
if (deb_check(prefix: 'vlc', release: '3.1', reference: '0.8.1.svn20050314-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package vlc is vulnerable in Debian sarge.\nUpgrade to vlc_0.8.1.svn20050314-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
