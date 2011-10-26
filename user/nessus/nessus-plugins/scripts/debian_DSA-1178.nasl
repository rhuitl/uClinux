# This script was automatically generated from the dsa-1178
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It was discovered that an integer overflow in freetype\'s PCF font code
may lead to denial of service and potential execution of arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.7-6.
For the unstable distribution (sid) this problem has been fixed in
version 2.2.1-5.
We recommend that you upgrade your freetype package.


Solution : http://www.debian.org/security/2006/dsa-1178
Risk factor : High';

if (description) {
 script_id(22720);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1178");
 script_cve_id("CVE-2006-3467");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1178] DSA-1178-1 freetype");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1178-1 freetype");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'freetype', release: '', reference: '2.2.1-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freetype is vulnerable in Debian .\nUpgrade to freetype_2.2.1-5\n');
}
if (deb_check(prefix: 'freetype2-demos', release: '3.1', reference: '2.1.7-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freetype2-demos is vulnerable in Debian 3.1.\nUpgrade to freetype2-demos_2.1.7-6\n');
}
if (deb_check(prefix: 'libfreetype6', release: '3.1', reference: '2.1.7-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreetype6 is vulnerable in Debian 3.1.\nUpgrade to libfreetype6_2.1.7-6\n');
}
if (deb_check(prefix: 'libfreetype6-dev', release: '3.1', reference: '2.1.7-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libfreetype6-dev is vulnerable in Debian 3.1.\nUpgrade to libfreetype6-dev_2.1.7-6\n');
}
if (deb_check(prefix: 'freetype', release: '3.1', reference: '2.1.7-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package freetype is vulnerable in Debian sarge.\nUpgrade to freetype_2.1.7-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
