# This script was automatically generated from the dsa-1137
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tavis Ormandy of the Google Security Team discovered several problems
in the TIFF library.  The Common Vulnerabilities and Exposures project
identifies the following issues:
    Several stack-buffer overflows have been discovered.
    A heap overflow vulnerability in the JPEG decoder may overrun a
    buffer with more data than expected.
    A heap overflow vulnerability in the PixarLog decoder may allow an
    attacker to execute arbitrary code.
    A heap overflow vulnerability has been discovered in the NeXT RLE
    decoder.
    An loop was discovered where a 16bit unsigned short was used to
    iterate over a 32bit unsigned value so that the loop would never
    terminate and continue forever.
    Multiple unchecked arithmetic operations were uncovered, including
    a number of the range checking operations designed to ensure the
    offsets specified in TIFF directories are legitimate.
    A flaw was also uncovered in libtiffs custom tag support which may
    result in abnormal behaviour, crashes, or potentially arbitrary
    code execution.
For the stable distribution (sarge) these problems have been fixed in
version 3.7.2-7.
For the unstable distribution (sid) these problems have been fixed in
version 3.8.2-6.
We recommend that you upgrade your libtiff packages.


Solution : http://www.debian.org/security/2006/dsa-1137
Risk factor : High';

if (description) {
 script_id(22679);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1137");
 script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1137] DSA-1137-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1137-1 tiff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tiff', release: '', reference: '3.8.2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian .\nUpgrade to tiff_3.8.2-6\n');
}
if (deb_check(prefix: 'libtiff-opengl', release: '3.1', reference: '3.7.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-opengl is vulnerable in Debian 3.1.\nUpgrade to libtiff-opengl_3.7.2-7\n');
}
if (deb_check(prefix: 'libtiff-tools', release: '3.1', reference: '3.7.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.1.\nUpgrade to libtiff-tools_3.7.2-7\n');
}
if (deb_check(prefix: 'libtiff4', release: '3.1', reference: '3.7.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff4 is vulnerable in Debian 3.1.\nUpgrade to libtiff4_3.7.2-7\n');
}
if (deb_check(prefix: 'libtiff4-dev', release: '3.1', reference: '3.7.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff4-dev is vulnerable in Debian 3.1.\nUpgrade to libtiff4-dev_3.7.2-7\n');
}
if (deb_check(prefix: 'libtiffxx0', release: '3.1', reference: '3.7.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiffxx0 is vulnerable in Debian 3.1.\nUpgrade to libtiffxx0_3.7.2-7\n');
}
if (deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian sarge.\nUpgrade to tiff_3.7.2-7\n');
}
if (w) { security_hole(port: 0, data: desc); }
