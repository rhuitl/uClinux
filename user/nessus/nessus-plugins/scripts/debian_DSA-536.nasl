# This script was automatically generated from the dsa-536
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered several vulnerabilities in libpng:
 Multiple buffer overflows exist, including when
 handling transparency chunk data, which could be exploited to cause
 arbitrary code to be executed when a specially crafted PNG image is
 processed
 Multiple NULL pointer dereferences in
 png_handle_iCPP() and elsewhere could be exploited to cause an
 application to crash when a specially crafted PNG image is processed
 Multiple integer overflows in the png_handle_sPLT(),
 png_read_png() functions and elsewhere could be exploited to cause an
 application to crash, or potentially arbitrary code to be executed,
 when a specially crafted PNG image is processed
In addition, a bug related to CVE-2002-1363 was fixed:
 A buffer overflow could be caused by incorrect
 calculation of buffer offsets, possibly leading to the execution of
 arbitrary code
For the current stable distribution (woody), these problems have been
fixed in libpng3 version 1.2.1-1.1.woody.7 and libpng version
1.0.12-3.woody.7.
For the unstable distribution (sid), these problems will be fixed soon.
We recommend that you update your libpng and libpng3 packages.


Solution : http://www.debian.org/security/2004/dsa-536
Risk factor : High';

if (description) {
 script_id(15373);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "536");
 script_cve_id("CVE-2004-0597", "CVE-2004-0598", "CVE-2004-0599", "CVE-2004-0768");
 script_xref(name: "CERT", value: "160448");
 script_xref(name: "CERT", value: "236656");
 script_xref(name: "CERT", value: "286464");
 script_xref(name: "CERT", value: "388984");
 script_xref(name: "CERT", value: "477512");
 script_xref(name: "CERT", value: "817368");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA536] DSA-536-1 libpng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-536-1 libpng");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libpng-dev', release: '3.0', reference: '1.2.1-1.1.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng-dev is vulnerable in Debian 3.0.\nUpgrade to libpng-dev_1.2.1-1.1.woody.7\n');
}
if (deb_check(prefix: 'libpng2', release: '3.0', reference: '1.0.12-3.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2 is vulnerable in Debian 3.0.\nUpgrade to libpng2_1.0.12-3.woody.7\n');
}
if (deb_check(prefix: 'libpng2-dev', release: '3.0', reference: '1.0.12-3.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng2-dev is vulnerable in Debian 3.0.\nUpgrade to libpng2-dev_1.0.12-3.woody.7\n');
}
if (deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng3 is vulnerable in Debian 3.0.\nUpgrade to libpng3_1.2.1-1.1.woody.7\n');
}
if (deb_check(prefix: 'libpng3', release: '3.0', reference: '1.2.1-1.1.woody')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libpng3 is vulnerable in Debian woody.\nUpgrade to libpng3_1.2.1-1.1.woody\n');
}
if (w) { security_hole(port: 0, data: desc); }
