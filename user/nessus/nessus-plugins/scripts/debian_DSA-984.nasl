# This script was automatically generated from the dsa-984
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Derek Noonburg has fixed several potential vulnerabilities in xpdf,
the Portable Document Format (PDF) suite.
The old stable distribution (woody) does not seem to be affected.
For the stable distribution (sarge) these problems have been fixed in
version 3.00-13.6.
For the unstable distribution (sid) these problems have been fixed in
version 3.01-7.
We recommend that you upgrade your xpdf packages.


Solution : http://www.debian.org/security/2006/dsa-984
Risk factor : High';

if (description) {
 script_id(22850);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "984");
 script_cve_id("CVE-2006-1244");
 script_bugtraq_id(16748);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA984] DSA-984-1 xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-984-1 xpdf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpdf', release: '', reference: '3.01-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian .\nUpgrade to xpdf_3.01-7\n');
}
if (deb_check(prefix: 'xpdf', release: '3.1', reference: '3.00-13.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian 3.1.\nUpgrade to xpdf_3.00-13.6\n');
}
if (deb_check(prefix: 'xpdf-common', release: '3.1', reference: '3.00-13.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-common is vulnerable in Debian 3.1.\nUpgrade to xpdf-common_3.00-13.6\n');
}
if (deb_check(prefix: 'xpdf-reader', release: '3.1', reference: '3.00-13.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-reader is vulnerable in Debian 3.1.\nUpgrade to xpdf-reader_3.00-13.6\n');
}
if (deb_check(prefix: 'xpdf-utils', release: '3.1', reference: '3.00-13.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-utils is vulnerable in Debian 3.1.\nUpgrade to xpdf-utils_3.00-13.6\n');
}
if (deb_check(prefix: 'xpdf', release: '3.1', reference: '3.00-13.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian sarge.\nUpgrade to xpdf_3.00-13.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
