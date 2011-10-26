# This script was automatically generated from the dsa-645
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE has reported a buffer overflow in xpdf, the portable document
format (PDF) suite.  Similar code is present in the PDF processing
part of CUPS.  A maliciously crafted PDF file could exploit this
problem, resulting in the execution of arbitrary code.
For the stable distribution (woody) this problem has been fixed in
version 1.1.14-5woody12.
In the unstable distribution (sid) CUPSYS does not use its own xpdf
variant anymore but uses xpdf-utils.
We recommend that you upgrade your cups packages.


Solution : http://www.debian.org/security/2005/dsa-645
Risk factor : High';

if (description) {
 script_id(16212);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "645");
 script_cve_id("CVE-2005-0064");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA645] DSA-645-1 cupsys");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-645-1 cupsys");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian 3.0.\nUpgrade to cupsys_1.1.14-5woody12\n');
}
if (deb_check(prefix: 'cupsys-bsd', release: '3.0', reference: '1.1.14-5woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-bsd is vulnerable in Debian 3.0.\nUpgrade to cupsys-bsd_1.1.14-5woody12\n');
}
if (deb_check(prefix: 'cupsys-client', release: '3.0', reference: '1.1.14-5woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-client is vulnerable in Debian 3.0.\nUpgrade to cupsys-client_1.1.14-5woody12\n');
}
if (deb_check(prefix: 'cupsys-pstoraster', release: '3.0', reference: '1.1.14-5woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys-pstoraster is vulnerable in Debian 3.0.\nUpgrade to cupsys-pstoraster_1.1.14-5woody12\n');
}
if (deb_check(prefix: 'libcupsys2', release: '3.0', reference: '1.1.14-5woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2 is vulnerable in Debian 3.0.\nUpgrade to libcupsys2_1.1.14-5woody12\n');
}
if (deb_check(prefix: 'libcupsys2-dev', release: '3.0', reference: '1.1.14-5woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libcupsys2-dev is vulnerable in Debian 3.0.\nUpgrade to libcupsys2-dev_1.1.14-5woody12\n');
}
if (deb_check(prefix: 'cupsys', release: '3.0', reference: '1.1.14-5woody12')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cupsys is vulnerable in Debian woody.\nUpgrade to cupsys_1.1.14-5woody12\n');
}
if (w) { security_hole(port: 0, data: desc); }
