# This script was automatically generated from the dsa-567
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several problems have been discovered in libtiff, the Tag Image File
Format library for processing TIFF graphics files.  An attacker could
prepare a specially crafted TIFF graphic that would cause the client
to execute arbitrary code or crash.  The Common Vulnerabilities and
Exposures Project has identified the following problems:
    Chris Evans discovered several problems in the RLE (run length
    encoding) decoders that could lead to arbitrary code execution.
    Matthias Clasen discovered a division by zero through an integer
    overflow.
    Dmitry V. Levin discovered several integer overflows that caused
    malloc issues which can result to either plain crash or memory
    corruption.
For the stable distribution (woody) these problems have been fixed in
version 3.5.5-6woody1.
For the unstable distribution (sid) these problems have been fixed in
version 3.6.1-2.
We recommend that you upgrade your libtiff package.


Solution : http://www.debian.org/security/2004/dsa-567
Risk factor : High';

if (description) {
 script_id(15665);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "567");
 script_cve_id("CVE-2004-0803", "CVE-2004-0804", "CVE-2004-0886");
 script_bugtraq_id(11406);
 script_xref(name: "CERT", value: "555304");
 script_xref(name: "CERT", value: "687568");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA567] DSA-567-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-567-1 tiff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.0.\nUpgrade to libtiff-tools_3.5.5-6woody1\n');
}
if (deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g is vulnerable in Debian 3.0.\nUpgrade to libtiff3g_3.5.5-6woody1\n');
}
if (deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g-dev is vulnerable in Debian 3.0.\nUpgrade to libtiff3g-dev_3.5.5-6woody1\n');
}
if (deb_check(prefix: 'tiff', release: '3.1', reference: '3.6.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian 3.1.\nUpgrade to tiff_3.6.1-2\n');
}
if (deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian woody.\nUpgrade to tiff_3.5.5-6woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
