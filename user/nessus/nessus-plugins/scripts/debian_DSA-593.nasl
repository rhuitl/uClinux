# This script was automatically generated from the dsa-593
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been reported for ImageMagick, a commonly used
image manipulation library.  Due to a boundary error within the EXIF
parsing routine, a specially crafted graphic image could lead to the
execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 5.4.4.5-1woody4.
For the unstable distribution (sid) this problem has been fixed in
version 6.0.6.2-1.5.
We recommend that you upgrade your imagemagick packages.


Solution : http://www.debian.org/security/2004/dsa-593
Risk factor : High';

if (description) {
 script_id(15728);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "593");
 script_cve_id("CVE-2004-0981");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA593] DSA-593-1 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-593-1 imagemagick");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian 3.0.\nUpgrade to imagemagick_5.4.4.5-1woody4\n');
}
if (deb_check(prefix: 'libmagick5', release: '3.0', reference: '5.4.4.5-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmagick5 is vulnerable in Debian 3.0.\nUpgrade to libmagick5_5.4.4.5-1woody4\n');
}
if (deb_check(prefix: 'libmagick5-dev', release: '3.0', reference: '5.4.4.5-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmagick5-dev is vulnerable in Debian 3.0.\nUpgrade to libmagick5-dev_5.4.4.5-1woody4\n');
}
if (deb_check(prefix: 'perlmagick', release: '3.0', reference: '5.4.4.5-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perlmagick is vulnerable in Debian 3.0.\nUpgrade to perlmagick_5.4.4.5-1woody4\n');
}
if (deb_check(prefix: 'imagemagick', release: '3.1', reference: '6.0.6.2-1.5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian 3.1.\nUpgrade to imagemagick_6.0.6.2-1.5\n');
}
if (deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian woody.\nUpgrade to imagemagick_5.4.4.5-1woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
