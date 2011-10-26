# This script was automatically generated from the dsa-890
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered several security related problems in libungif4,
a shared library for GIF images.  The Common Vulnerabilities and
Exposures project identifies the following vulnerabilities:
    Null pointer dereference, that could cause a denial of service.
    Out of bounds memory access that could cause a denial of service
    or the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 4.1.0b1-2woody1.
For the stable distribution (sarge) these problems have been fixed in
version 4.1.3-2sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your libungif4 packages.


Solution : http://www.debian.org/security/2005/dsa-890
Risk factor : High';

if (description) {
 script_id(22756);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "890");
 script_cve_id("CVE-2005-2974", "CVE-2005-3350");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA890] DSA-890-1 libungif4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-890-1 libungif4");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libungif-bin', release: '3.0', reference: '4.1.0b1-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libungif-bin is vulnerable in Debian 3.0.\nUpgrade to libungif-bin_4.1.0b1-2woody1\n');
}
if (deb_check(prefix: 'libungif4-dev', release: '3.0', reference: '4.1.0b1-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libungif4-dev is vulnerable in Debian 3.0.\nUpgrade to libungif4-dev_4.1.0b1-2woody1\n');
}
if (deb_check(prefix: 'libungif4g', release: '3.0', reference: '4.1.0b1-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libungif4g is vulnerable in Debian 3.0.\nUpgrade to libungif4g_4.1.0b1-2woody1\n');
}
if (deb_check(prefix: 'libungif-bin', release: '3.1', reference: '4.1.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libungif-bin is vulnerable in Debian 3.1.\nUpgrade to libungif-bin_4.1.3-2sarge1\n');
}
if (deb_check(prefix: 'libungif4-dev', release: '3.1', reference: '4.1.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libungif4-dev is vulnerable in Debian 3.1.\nUpgrade to libungif4-dev_4.1.3-2sarge1\n');
}
if (deb_check(prefix: 'libungif4g', release: '3.1', reference: '4.1.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libungif4g is vulnerable in Debian 3.1.\nUpgrade to libungif4g_4.1.3-2sarge1\n');
}
if (deb_check(prefix: 'libungif4', release: '3.1', reference: '4.1.3-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libungif4 is vulnerable in Debian sarge.\nUpgrade to libungif4_4.1.3-2sarge1\n');
}
if (deb_check(prefix: 'libungif4', release: '3.0', reference: '4.1.0b1-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libungif4 is vulnerable in Debian woody.\nUpgrade to libungif4_4.1.0b1-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
