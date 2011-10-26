# This script was automatically generated from the dsa-695
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in xli, an image viewer
for X11.  The Common Vulnerabilities and Exposures project identifies
the following problems:
    A buffer overflow in the decoder for FACES format images could be
    exploited by an attacker to execute arbitrary code.  This problem
    has already been fixed in xloadimage in
    DSA 069.
    Tavis Ormandy of the Gentoo Linux Security Audit Team has reported
    a flaw in the handling of compressed images, where shell
    meta-characters are not adequately escaped.
    Insufficient validation of image properties in have been
    discovered which could potentially result in buffer management
    errors.
For the stable distribution (woody) these problems have been fixed in
version 1.17.0-11woody1.
For the unstable distribution (sid) these problems have been fixed in
version 1.17.0-18.
We recommend that you upgrade your xli package.


Solution : http://www.debian.org/security/2005/dsa-695
Risk factor : High';

if (description) {
 script_id(17578);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "695");
 script_cve_id("CVE-2001-0775", "CVE-2005-0638", "CVE-2005-0639");
 script_bugtraq_id(3006);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA695] DSA-695-1 xli");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-695-1 xli");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xli', release: '3.0', reference: '1.17.0-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xli is vulnerable in Debian 3.0.\nUpgrade to xli_1.17.0-11woody1\n');
}
if (deb_check(prefix: 'xli', release: '3.1', reference: '1.17.0-18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xli is vulnerable in Debian 3.1.\nUpgrade to xli_1.17.0-18\n');
}
if (deb_check(prefix: 'xli', release: '3.0', reference: '1.17.0-11woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xli is vulnerable in Debian woody.\nUpgrade to xli_1.17.0-11woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
