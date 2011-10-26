# This script was automatically generated from the dsa-1091
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in the TIFF library.  The Common
Vulnerabilities and Exposures project identifies the following issues:
    SuSE discovered a buffer overflow in the conversion of TIFF files
    into PDF documents which could be exploited when tiff2pdf is used
    e.g. in a printer filter.
    The tiffsplit command from the TIFF library contains a buffer
    overflow in the commandline handling which could be exploited when
    the program is executed automatically on unknown filenames.
For the old stable distribution (woody) this problem has been fixed in
version 3.5.5-7woody2.
For the stable distribution (sarge) this problem has been fixed in
version 3.7.2-5.
For the unstable distribution (sid) this problem has been fixed in
version 3.8.2-4.
We recommend that you upgrade your tiff packages.


Solution : http://www.debian.org/security/2006/dsa-1091
Risk factor : High';

if (description) {
 script_id(22633);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1091");
 script_cve_id("CVE-2006-2193", "CVE-2006-2656");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1091] DSA-1091-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1091-1 tiff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tiff', release: '', reference: '3.8.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian .\nUpgrade to tiff_3.8.2-4\n');
}
if (deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-7woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.0.\nUpgrade to libtiff-tools_3.5.5-7woody2\n');
}
if (deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-7woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g is vulnerable in Debian 3.0.\nUpgrade to libtiff3g_3.5.5-7woody2\n');
}
if (deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-7woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g-dev is vulnerable in Debian 3.0.\nUpgrade to libtiff3g-dev_3.5.5-7woody2\n');
}
if (deb_check(prefix: 'libtiff-opengl', release: '3.1', reference: '3.7.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-opengl is vulnerable in Debian 3.1.\nUpgrade to libtiff-opengl_3.7.2-5\n');
}
if (deb_check(prefix: 'libtiff-tools', release: '3.1', reference: '3.7.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.1.\nUpgrade to libtiff-tools_3.7.2-5\n');
}
if (deb_check(prefix: 'libtiff4', release: '3.1', reference: '3.7.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff4 is vulnerable in Debian 3.1.\nUpgrade to libtiff4_3.7.2-5\n');
}
if (deb_check(prefix: 'libtiff4-dev', release: '3.1', reference: '3.7.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff4-dev is vulnerable in Debian 3.1.\nUpgrade to libtiff4-dev_3.7.2-5\n');
}
if (deb_check(prefix: 'libtiffxx0', release: '3.1', reference: '3.7.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiffxx0 is vulnerable in Debian 3.1.\nUpgrade to libtiffxx0_3.7.2-5\n');
}
if (deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian sarge.\nUpgrade to tiff_3.7.2-5\n');
}
if (deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-7woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian woody.\nUpgrade to tiff_3.5.5-7woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
