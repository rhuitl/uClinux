# This script was automatically generated from the dsa-887
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in Clam AntiVirus, the
antivirus scanner for Unix, designed for integration with mail servers
to perform attachment scanning.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    The OLE2 unpacker allows remote attackers to cause a segmentation
    fault via a DOC file with an invalid property tree, which triggers
    an infinite recursion.
    A specially crafted executable compressed with FSG 1.33 could
    cause the extractor to write beyond buffer boundaries, allowing an
    attacker to execute arbitrary code.
    A specially crafted CAB file could cause ClamAV to be locked in an
    infinite loop and use all available processor resources, resulting
    in a denial of service.
    A specially crafted CAB file could cause ClamAV to be locked in an
    infinite loop and use all available processor resources, resulting
    in a denial of service.
The old stable distribution (woody) does not contain clamav packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.84-2.sarge.6.
For the unstable distribution (sid) these problems have been fixed in
version 0.87.1-1.
We recommend that you upgrade your clamav packages.


Solution : http://www.debian.org/security/2005/dsa-887
Risk factor : High';

if (description) {
 script_id(22753);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "887");
 script_cve_id("CVE-2005-3239", "CVE-2005-3303", "CVE-2005-3500", "CVE-2005-3501");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA887] DSA-887-1 clamav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-887-1 clamav");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'clamav', release: '', reference: '0.87.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav is vulnerable in Debian .\nUpgrade to clamav_0.87.1-1\n');
}
if (deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav is vulnerable in Debian 3.1.\nUpgrade to clamav_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'clamav-base', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-base is vulnerable in Debian 3.1.\nUpgrade to clamav-base_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'clamav-daemon', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-daemon is vulnerable in Debian 3.1.\nUpgrade to clamav-daemon_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'clamav-docs', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-docs is vulnerable in Debian 3.1.\nUpgrade to clamav-docs_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'clamav-freshclam', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-freshclam is vulnerable in Debian 3.1.\nUpgrade to clamav-freshclam_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'clamav-milter', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-milter is vulnerable in Debian 3.1.\nUpgrade to clamav-milter_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'clamav-testfiles', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav-testfiles is vulnerable in Debian 3.1.\nUpgrade to clamav-testfiles_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'libclamav-dev', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libclamav-dev is vulnerable in Debian 3.1.\nUpgrade to libclamav-dev_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'libclamav1', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libclamav1 is vulnerable in Debian 3.1.\nUpgrade to libclamav1_0.84-2.sarge.6\n');
}
if (deb_check(prefix: 'clamav', release: '3.1', reference: '0.84-2.sarge.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package clamav is vulnerable in Debian sarge.\nUpgrade to clamav_0.84-2.sarge.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
