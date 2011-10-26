# This script was automatically generated from the dsa-222
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE discovered an integer overflow in the pdftops filter from the
xpdf package that can be exploited to gain the privileges of the
target user.  This can lead to gaining unauthorized access to the \'lp\'
user if the pdftops program is part of the print filter.
For the current stable distribution (woody) this problem has been
fixed in version 1.00-3.1.
For the old stable distribution (potato) this problem has been
fixed in version 0.90-8.1.
For the unstable distribution (sid) this problem has been
fixed in version 2.01-2.
We recommend that you upgrade your xpdf package.


Solution : http://www.debian.org/security/2003/dsa-222
Risk factor : High';

if (description) {
 script_id(15059);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "222");
 script_cve_id("CVE-2002-1384");
 script_bugtraq_id(6475);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA222] DSA-222-1 xpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-222-1 xpdf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpdf', release: '2.2', reference: '0.90-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian 2.2.\nUpgrade to xpdf_0.90-8.1\n');
}
if (deb_check(prefix: 'xpdf', release: '3.0', reference: '1.00-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian 3.0.\nUpgrade to xpdf_1.00-3.1\n');
}
if (deb_check(prefix: 'xpdf-common', release: '3.0', reference: '1.00-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-common is vulnerable in Debian 3.0.\nUpgrade to xpdf-common_1.00-3.1\n');
}
if (deb_check(prefix: 'xpdf-reader', release: '3.0', reference: '1.00-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-reader is vulnerable in Debian 3.0.\nUpgrade to xpdf-reader_1.00-3.1\n');
}
if (deb_check(prefix: 'xpdf-utils', release: '3.0', reference: '1.00-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-utils is vulnerable in Debian 3.0.\nUpgrade to xpdf-utils_1.00-3.1\n');
}
if (deb_check(prefix: 'xpdf', release: '3.1', reference: '2.01-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian 3.1.\nUpgrade to xpdf_2.01-2\n');
}
if (deb_check(prefix: 'xpdf', release: '2.2', reference: '0.90-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian potato.\nUpgrade to xpdf_0.90-8.1\n');
}
if (deb_check(prefix: 'xpdf', release: '3.0', reference: '1.00-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf is vulnerable in Debian woody.\nUpgrade to xpdf_1.00-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
