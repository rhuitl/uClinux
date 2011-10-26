# This script was automatically generated from the dsa-1078
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Andrey Kiselev discovered a problem in the TIFF library that may allow
an attacker with a specially crafted TIFF image with Yr/Yg/Yb values
that exceed the YCR/YCG/YCB values to crash the library and hence the
surrounding application.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.7.2-4.
The unstable distribution (sid) is not affected by this problem.
We recommend that you upgrade your tiff packages and restart the
programs using it.


Solution : http://www.debian.org/security/2006/dsa-1078
Risk factor : High';

if (description) {
 script_id(22620);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1078");
 script_cve_id("CVE-2006-2120");
 script_bugtraq_id(17809);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1078] DSA-1078-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1078-1 tiff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtiff-opengl', release: '3.1', reference: '3.7.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-opengl is vulnerable in Debian 3.1.\nUpgrade to libtiff-opengl_3.7.2-4\n');
}
if (deb_check(prefix: 'libtiff-tools', release: '3.1', reference: '3.7.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.1.\nUpgrade to libtiff-tools_3.7.2-4\n');
}
if (deb_check(prefix: 'libtiff4', release: '3.1', reference: '3.7.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff4 is vulnerable in Debian 3.1.\nUpgrade to libtiff4_3.7.2-4\n');
}
if (deb_check(prefix: 'libtiff4-dev', release: '3.1', reference: '3.7.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff4-dev is vulnerable in Debian 3.1.\nUpgrade to libtiff4-dev_3.7.2-4\n');
}
if (deb_check(prefix: 'libtiffxx0', release: '3.1', reference: '3.7.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiffxx0 is vulnerable in Debian 3.1.\nUpgrade to libtiffxx0_3.7.2-4\n');
}
if (deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian sarge.\nUpgrade to tiff_3.7.2-4\n');
}
if (w) { security_hole(port: 0, data: desc); }
