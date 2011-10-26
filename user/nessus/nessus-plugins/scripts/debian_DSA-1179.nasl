# This script was automatically generated from the dsa-1179
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Luigi Auriemma discovered several buffer overflows in alsaplayer, a
PCM player designed for ALSA, that can lead to a crash of the
application and maybe worse outcome.
For the stable distribution (sarge) these problems have been fixed in
version 0.99.76-0.3sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your alsaplayer package.


Solution : http://www.debian.org/security/2006/dsa-1179
Risk factor : High';

if (description) {
 script_id(22721);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1179");
 script_cve_id("CVE-2006-4089");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1179] DSA-1179-1 alsaplayer");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1179-1 alsaplayer");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'alsaplayer', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer is vulnerable in Debian 3.1.\nUpgrade to alsaplayer_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-alsa', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-alsa is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-alsa_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-common', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-common is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-common_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-daemon', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-daemon is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-daemon_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-esd', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-esd is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-esd_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-gtk', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-gtk is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-gtk_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-jack', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-jack is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-jack_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-nas', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-nas is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-nas_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-oss', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-oss is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-oss_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-text', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-text is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-text_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer-xosd', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer-xosd is vulnerable in Debian 3.1.\nUpgrade to alsaplayer-xosd_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'libalsaplayer-dev', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libalsaplayer-dev is vulnerable in Debian 3.1.\nUpgrade to libalsaplayer-dev_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'libalsaplayer0', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libalsaplayer0 is vulnerable in Debian 3.1.\nUpgrade to libalsaplayer0_0.99.76-0.3sarge1\n');
}
if (deb_check(prefix: 'alsaplayer', release: '3.1', reference: '0.99.76-0.3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package alsaplayer is vulnerable in Debian sarge.\nUpgrade to alsaplayer_0.99.76-0.3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
