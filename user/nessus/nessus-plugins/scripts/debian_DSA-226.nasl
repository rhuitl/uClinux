# This script was automatically generated from the dsa-226
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
iDEFENSE discovered an integer overflow in the pdftops filter from the
xpdf and xpdf-i packages that can be exploited to gain the privileges
of the target user.  This can lead to gaining unauthorized access to the
\'lp\' user if the pdftops program is part of the print filter.
For the current stable distribution (woody) xpdf-i is only a dummy
package and the problem was fixed in xpdf already.
For the old stable distribution (potato) this problem has been
fixed in version 0.90-8.1.
For the unstable distribution (sid) this problem has been
fixed in version 2.01-2.
We recommend that you upgrade your xpdf-i package.


Solution : http://www.debian.org/security/2003/dsa-226
Risk factor : High';

if (description) {
 script_id(15063);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "226");
 script_cve_id("CVE-2002-1384");
 script_bugtraq_id(6475);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA226] DSA-226-1 xpdf-i");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-226-1 xpdf-i");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xpdf-i', release: '2.2', reference: '0.90-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-i is vulnerable in Debian 2.2.\nUpgrade to xpdf-i_0.90-8.1\n');
}
if (deb_check(prefix: 'xpdf-i', release: '3.0', reference: '2.01-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-i is vulnerable in Debian 3.0.\nUpgrade to xpdf-i_2.01-2\n');
}
if (deb_check(prefix: 'xpdf-i', release: '2.2', reference: '0.90-8.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xpdf-i is vulnerable in Debian potato.\nUpgrade to xpdf-i_0.90-8.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
