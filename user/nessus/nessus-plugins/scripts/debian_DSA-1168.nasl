# This script was automatically generated from the dsa-1168
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several remote vulnerabilities have been discovered in Imagemagick, a
collection of image manipulation tools, which may lead to the execution
of arbitrary code. The Common Vulnerabilities and Exposures project
identifies the following problems:
    Eero Häkkinen discovered that the display tool allocates insufficient
    memory for globbing patterns, which might lead to a buffer overflow.
    Tavis Ormandy from the Google Security Team discovered that the Sun
    bitmap decoder performs insufficient input sanitising, which might
    lead to buffer overflows and the execution of arbitrary code.
    Tavis Ormandy from the Google Security Team discovered that the XCF
    image decoder performs insufficient input sanitising, which might
    lead to buffer overflows and the execution of arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 6:6.0.6.2-2.7.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your imagemagick packages.


Solution : http://www.debian.org/security/2006/dsa-1168
Risk factor : High';

if (description) {
 script_id(22710);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1168");
 script_cve_id("CVE-2006-2440", "CVE-2006-3743", "CVE-2006-3744");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1168] DSA-1168-1 imagemagick");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1168-1 imagemagick");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'imagemagick', release: '3.1', reference: '6.0.6.2-2.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian 3.1.\nUpgrade to imagemagick_6.0.6.2-2.7\n');
}
if (deb_check(prefix: 'libmagick6', release: '3.1', reference: '6.0.6.2-2.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmagick6 is vulnerable in Debian 3.1.\nUpgrade to libmagick6_6.0.6.2-2.7\n');
}
if (deb_check(prefix: 'libmagick6-dev', release: '3.1', reference: '6.0.6.2-2.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmagick6-dev is vulnerable in Debian 3.1.\nUpgrade to libmagick6-dev_6.0.6.2-2.7\n');
}
if (deb_check(prefix: 'perlmagick', release: '3.1', reference: '6.0.6.2-2.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package perlmagick is vulnerable in Debian 3.1.\nUpgrade to perlmagick_6.0.6.2-2.7\n');
}
if (deb_check(prefix: 'imagemagick', release: '3.1', reference: '6.0.6.2-2.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imagemagick is vulnerable in Debian sarge.\nUpgrade to imagemagick_6.0.6.2-2.7\n');
}
if (w) { security_hole(port: 0, data: desc); }
