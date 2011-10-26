# This script was automatically generated from the dsa-737
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A number of potential remote denial of service vulnerabilities have been identified in
ClamAV. In addition to the four issues identified by CVE ID above, there
are fixes for issues in libclamav/cvd.c and libclamav/message.c.
Together, these issues could allow a carefully crafted message to crash
a ClamAV scanner or exhaust various resources on the machine running the
scanner.
For the stable distribution (sarge), these problems have been fixed in
version 0.84-2.sarge.1. 
We recommend that you upgrade your clamav package.


Solution : http://www.debian.org/security/2005/dsa-737
Risk factor : High';

if (description) {
 script_id(18629);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "737");
 script_cve_id("CVE-2005-1922", "CVE-2005-1923", "CVE-2005-2056", "CVE-2005-2070");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA737] DSA-737-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-737-1 clamav");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav is vulnerable in Debian 3.1.\nUpgrade to clamav_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'clamav-base', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-base is vulnerable in Debian 3.1.\nUpgrade to clamav-base_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'clamav-daemon', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-daemon is vulnerable in Debian 3.1.\nUpgrade to clamav-daemon_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'clamav-docs', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-docs is vulnerable in Debian 3.1.\nUpgrade to clamav-docs_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'clamav-freshclam', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-freshclam is vulnerable in Debian 3.1.\nUpgrade to clamav-freshclam_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'clamav-milter', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-milter is vulnerable in Debian 3.1.\nUpgrade to clamav-milter_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'clamav-testfiles', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-testfiles is vulnerable in Debian 3.1.\nUpgrade to clamav-testfiles_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'libclamav-dev', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libclamav-dev is vulnerable in Debian 3.1.\nUpgrade to libclamav-dev_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'libclamav1', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libclamav1 is vulnerable in Debian 3.1.\nUpgrade to libclamav1_0.84-2.sarge.1\n');
}
if (deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav is vulnerable in Debian sarge.\nUpgrade to clamav_0.84-2.sarge.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
