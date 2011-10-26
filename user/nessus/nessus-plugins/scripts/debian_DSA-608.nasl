# This script was automatically generated from the dsa-608
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in zgv, an SVGAlib
graphics viewer for the i386 architecture.  The Common Vulnerabilities
and Exposures Project identifies the following problems:
    "infamous41md" discovered multiple
    integer overflows in zgv.  Remote exploitation of an integer
    overflow vulnerability could allow the execution of arbitrary
    code.
    Mikulas Patocka discovered that malicious multiple-image (e.g.
    animated) GIF images can cause a segmentation fault in zgv.
For the stable distribution (woody) these problems have been fixed in
version 5.5-3woody1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your zgv package immediately.


Solution : http://www.debian.org/security/2004/dsa-608
Risk factor : High';

if (description) {
 script_id(15953);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "608");
 script_cve_id("CVE-2004-0999", "CVE-2004-1095");
 script_bugtraq_id(11556);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA608] DSA-608-1 zgv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-608-1 zgv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zgv', release: '3.0', reference: '5.5-3woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zgv is vulnerable in Debian 3.0.\nUpgrade to zgv_5.5-3woody2\n');
}
if (deb_check(prefix: 'zgv', release: '3.0', reference: '5.5-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zgv is vulnerable in Debian woody.\nUpgrade to zgv_5.5-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
