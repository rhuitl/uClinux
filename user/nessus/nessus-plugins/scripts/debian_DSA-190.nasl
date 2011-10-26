# This script was automatically generated from the dsa-190
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Al Viro found a problem in the image handling code use in Window Maker,
a popular NEXTSTEP like window manager. When creating an image it would
allocate a buffer by multiplying the image width and height, but did not
check for an overflow. This makes it possible to overflow the buffer.
This could be exploited by using specially crafted image files (for
example when previewing themes).
This problem has been fixed in version 0.80.0-4.1 for the current stable
distribution (woody).  Packages for the mipsel architecture are not yet
available.


Solution : http://www.debian.org/security/2002/dsa-190
Risk factor : High';

if (description) {
 script_id(15027);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "190");
 script_cve_id("CVE-2002-1277");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA190] DSA-190-1 wmaker");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-190-1 wmaker");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libwings-dev', release: '3.0', reference: '0.80.0-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwings-dev is vulnerable in Debian 3.0.\nUpgrade to libwings-dev_0.80.0-4.1\n');
}
if (deb_check(prefix: 'libwmaker0-dev', release: '3.0', reference: '0.80.0-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwmaker0-dev is vulnerable in Debian 3.0.\nUpgrade to libwmaker0-dev_0.80.0-4.1\n');
}
if (deb_check(prefix: 'libwraster2', release: '3.0', reference: '0.80.0-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwraster2 is vulnerable in Debian 3.0.\nUpgrade to libwraster2_0.80.0-4.1\n');
}
if (deb_check(prefix: 'libwraster2-dev', release: '3.0', reference: '0.80.0-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libwraster2-dev is vulnerable in Debian 3.0.\nUpgrade to libwraster2-dev_0.80.0-4.1\n');
}
if (deb_check(prefix: 'wmaker', release: '3.0', reference: '0.80.0-4.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wmaker is vulnerable in Debian 3.0.\nUpgrade to wmaker_0.80.0-4.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
