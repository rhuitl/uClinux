# This script was automatically generated from the dsa-1054
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Tavis Ormandy discovered several vulnerabilities in the TIFF library
that can lead to a denial of service or the execution of arbitrary
code.  The Common Vulnerabilities and Exposures project identifies the
following problems:
    Multiple vulnerabilities allow attackers to cause a denial of
    service.
    An integer overflow allows attackers to cause a denial of service
    and possibly execute arbitrary code.
    A double-free vulnerability allows attackers to cause a denial of
    service and possibly execute arbitrary code.
For the old stable distribution (woody) these problems have been fixed
in version 3.5.5-7woody1.
For the stable distribution (sarge) these problems have been fixed in
version 3.7.2-3sarge1.
The unstable distribution (sid) is not vulnerable to these problems.
We recommend that you upgrade your libtiff packages.


Solution : http://www.debian.org/security/2006/dsa-1054
Risk factor : High';

if (description) {
 script_id(22596);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1054");
 script_cve_id("CVE-2006-2024", "CVE-2006-2025", "CVE-2006-2026");
 script_bugtraq_id(17730, 17732, 17733);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1054] DSA-1054-1 tiff");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1054-1 tiff");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libtiff-tools', release: '3.0', reference: '3.5.5-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.0.\nUpgrade to libtiff-tools_3.5.5-7woody1\n');
}
if (deb_check(prefix: 'libtiff3g', release: '3.0', reference: '3.5.5-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g is vulnerable in Debian 3.0.\nUpgrade to libtiff3g_3.5.5-7woody1\n');
}
if (deb_check(prefix: 'libtiff3g-dev', release: '3.0', reference: '3.5.5-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff3g-dev is vulnerable in Debian 3.0.\nUpgrade to libtiff3g-dev_3.5.5-7woody1\n');
}
if (deb_check(prefix: 'libtiff-opengl', release: '3.1', reference: '3.7.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-opengl is vulnerable in Debian 3.1.\nUpgrade to libtiff-opengl_3.7.2-3sarge1\n');
}
if (deb_check(prefix: 'libtiff-tools', release: '3.1', reference: '3.7.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff-tools is vulnerable in Debian 3.1.\nUpgrade to libtiff-tools_3.7.2-3sarge1\n');
}
if (deb_check(prefix: 'libtiff4', release: '3.1', reference: '3.7.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff4 is vulnerable in Debian 3.1.\nUpgrade to libtiff4_3.7.2-3sarge1\n');
}
if (deb_check(prefix: 'libtiff4-dev', release: '3.1', reference: '3.7.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiff4-dev is vulnerable in Debian 3.1.\nUpgrade to libtiff4-dev_3.7.2-3sarge1\n');
}
if (deb_check(prefix: 'libtiffxx0', release: '3.1', reference: '3.7.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libtiffxx0 is vulnerable in Debian 3.1.\nUpgrade to libtiffxx0_3.7.2-3sarge1\n');
}
if (deb_check(prefix: 'tiff', release: '3.1', reference: '3.7.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian sarge.\nUpgrade to tiff_3.7.2-3sarge1\n');
}
if (deb_check(prefix: 'tiff', release: '3.0', reference: '3.5.5-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tiff is vulnerable in Debian woody.\nUpgrade to tiff_3.5.5-7woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
