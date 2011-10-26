# This script was automatically generated from the dsa-957
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Florian Weimer discovered that delegate code in ImageMagick is
vulnerable to shell command injection using specially crafted file
names.  This allows attackers to encode commands inside of graphic
commands.  With some user interaction, this is exploitable through
Gnus and Thunderbird.  This update filters out the \'$\' character as
well, which was forgotton in the former update.
For the old stable distribution (woody) this problem has been fixed in
version 5.4.4.5-1woody8.
For the stable distribution (sarge) this problem has been fixed in
version 6.0.6.2-2.6.
For the unstable distribution (sid) this problem has been fixed in
version 6.2.4.5-0.6.
We recommend that you upgrade your imagemagick packages.


Solution : http://www.debian.org/security/2006/dsa-957
Risk factor : High';

if (description) {
 script_id(22823);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "957");
 script_cve_id("CVE-2005-4601");
 script_bugtraq_id(16093);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA957] DSA-957-2 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-957-2 imagemagick");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'imagemagick', release: '', reference: '6.2.4.5-0.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian .\nUpgrade to imagemagick_6.2.4.5-0.6\n');
}
if (deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian 3.0.\nUpgrade to imagemagick_5.4.4.5-1woody8\n');
}
if (deb_check(prefix: 'libmagick5', release: '3.0', reference: '5.4.4.5-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmagick5 is vulnerable in Debian 3.0.\nUpgrade to libmagick5_5.4.4.5-1woody8\n');
}
if (deb_check(prefix: 'libmagick5-dev', release: '3.0', reference: '5.4.4.5-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmagick5-dev is vulnerable in Debian 3.0.\nUpgrade to libmagick5-dev_5.4.4.5-1woody8\n');
}
if (deb_check(prefix: 'perlmagick', release: '3.0', reference: '5.4.4.5-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perlmagick is vulnerable in Debian 3.0.\nUpgrade to perlmagick_5.4.4.5-1woody8\n');
}
if (deb_check(prefix: 'imagemagick', release: '3.1', reference: '6.0.6.2-2.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian 3.1.\nUpgrade to imagemagick_6.0.6.2-2.6\n');
}
if (deb_check(prefix: 'libmagick6', release: '3.1', reference: '6.0.6.2-2.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmagick6 is vulnerable in Debian 3.1.\nUpgrade to libmagick6_6.0.6.2-2.6\n');
}
if (deb_check(prefix: 'libmagick6-dev', release: '3.1', reference: '6.0.6.2-2.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmagick6-dev is vulnerable in Debian 3.1.\nUpgrade to libmagick6-dev_6.0.6.2-2.6\n');
}
if (deb_check(prefix: 'perlmagick', release: '3.1', reference: '6.0.6.2-2.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perlmagick is vulnerable in Debian 3.1.\nUpgrade to perlmagick_6.0.6.2-2.6\n');
}
if (deb_check(prefix: 'imagemagick', release: '3.1', reference: '6.0.6.2-2.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian sarge.\nUpgrade to imagemagick_6.0.6.2-2.6\n');
}
if (deb_check(prefix: 'imagemagick', release: '3.0', reference: '5.4.4.5-1woody8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian woody.\nUpgrade to imagemagick_5.4.4.5-1woody8\n');
}
if (w) { security_hole(port: 0, data: desc); }
