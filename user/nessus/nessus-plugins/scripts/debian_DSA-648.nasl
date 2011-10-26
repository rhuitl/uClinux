# This script was automatically generated from the dsa-648
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE has reported a buffer overflow in xpdf, the portable document
format (PDF) suite.  A maliciously crafted PDF file could exploit this
problem, resulting in the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 1.00-3.4.
For the unstable distribution (sid) this problem has been fixed in
version 3.00-12.
We recommend that you upgrade your xpdf package.


Solution : http://www.debian.org/security/2005/dsa-648
Risk factor : High';

if (description) {
 script_id(16215);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "648");
 script_cve_id("CVE-2005-0064");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA648] DSA-648-1 xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-648-1 xpdf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpdf', release: '3.0', reference: '1.00-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian 3.0.\nUpgrade to xpdf_1.00-3.4\n');
}
if (deb_check(prefix: 'xpdf-common', release: '3.0', reference: '1.00-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-common is vulnerable in Debian 3.0.\nUpgrade to xpdf-common_1.00-3.4\n');
}
if (deb_check(prefix: 'xpdf-reader', release: '3.0', reference: '1.00-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-reader is vulnerable in Debian 3.0.\nUpgrade to xpdf-reader_1.00-3.4\n');
}
if (deb_check(prefix: 'xpdf-utils', release: '3.0', reference: '1.00-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-utils is vulnerable in Debian 3.0.\nUpgrade to xpdf-utils_1.00-3.4\n');
}
if (deb_check(prefix: 'xpdf', release: '3.1', reference: '3.00-12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian 3.1.\nUpgrade to xpdf_3.00-12\n');
}
if (deb_check(prefix: 'xpdf', release: '3.0', reference: '1.00-3.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian woody.\nUpgrade to xpdf_1.00-3.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
