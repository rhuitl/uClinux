# This script was automatically generated from the dsa-931
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" and Chris Evans discovered several heap based buffer
overflows in xpdf, the Portable Document Format (PDF) suite, that can
lead to a denial of service by crashing the application or possibly to
the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 1.00-3.8.
For the stable distribution (sarge) these problems have been fixed in
version 3.00-13.4.
For the unstable distribution (sid) these problems have been fixed in
version 3.01-4.
We recommend that you upgrade your xpdf package.


Solution : http://www.debian.org/security/2006/dsa-931
Risk factor : High';

if (description) {
 script_id(22797);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "931");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA931] DSA-931-1 xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-931-1 xpdf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpdf', release: '', reference: '3.01-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian .\nUpgrade to xpdf_3.01-4\n');
}
if (deb_check(prefix: 'xpdf', release: '3.0', reference: '1.00-3.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian 3.0.\nUpgrade to xpdf_1.00-3.8\n');
}
if (deb_check(prefix: 'xpdf-common', release: '3.0', reference: '1.00-3.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-common is vulnerable in Debian 3.0.\nUpgrade to xpdf-common_1.00-3.8\n');
}
if (deb_check(prefix: 'xpdf-reader', release: '3.0', reference: '1.00-3.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-reader is vulnerable in Debian 3.0.\nUpgrade to xpdf-reader_1.00-3.8\n');
}
if (deb_check(prefix: 'xpdf-utils', release: '3.0', reference: '1.00-3.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-utils is vulnerable in Debian 3.0.\nUpgrade to xpdf-utils_1.00-3.8\n');
}
if (deb_check(prefix: 'xpdf', release: '3.1', reference: '3.00-13.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian 3.1.\nUpgrade to xpdf_3.00-13.4\n');
}
if (deb_check(prefix: 'xpdf-common', release: '3.1', reference: '3.00-13.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-common is vulnerable in Debian 3.1.\nUpgrade to xpdf-common_3.00-13.4\n');
}
if (deb_check(prefix: 'xpdf-reader', release: '3.1', reference: '3.00-13.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-reader is vulnerable in Debian 3.1.\nUpgrade to xpdf-reader_3.00-13.4\n');
}
if (deb_check(prefix: 'xpdf-utils', release: '3.1', reference: '3.00-13.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-utils is vulnerable in Debian 3.1.\nUpgrade to xpdf-utils_3.00-13.4\n');
}
if (deb_check(prefix: 'xpdf', release: '3.1', reference: '3.00-13.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian sarge.\nUpgrade to xpdf_3.00-13.4\n');
}
if (deb_check(prefix: 'xpdf', release: '3.0', reference: '1.00-3.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian woody.\nUpgrade to xpdf_1.00-3.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
