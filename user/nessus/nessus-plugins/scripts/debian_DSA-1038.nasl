# This script was automatically generated from the dsa-1038
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Andrea Barisani discovered that xzgv, a picture viewer for X with a
thumbnail-based selector, attempts to decode JPEG images within the
CMYK/YCCK colour space incorrectly, which could lead to the execution
of arbitrary code.
For the old stable distribution (woody) this problem has been fixed in
version 0.7-6woody3.
For the stable distribution (sarge) this problem has been fixed in
version 0.8-3sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your xzgv package.


Solution : http://www.debian.org/security/2006/dsa-1038
Risk factor : High';

if (description) {
 script_id(22580);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1038");
 script_cve_id("CVE-2006-1060");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1038] DSA-1038-1 xzgv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1038-1 xzgv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xzgv', release: '3.0', reference: '0.7-6woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xzgv is vulnerable in Debian 3.0.\nUpgrade to xzgv_0.7-6woody3\n');
}
if (deb_check(prefix: 'xzgv', release: '3.1', reference: '0.8-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xzgv is vulnerable in Debian 3.1.\nUpgrade to xzgv_0.8-3sarge1\n');
}
if (deb_check(prefix: 'xzgv', release: '3.1', reference: '0.8-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xzgv is vulnerable in Debian sarge.\nUpgrade to xzgv_0.8-3sarge1\n');
}
if (deb_check(prefix: 'xzgv', release: '3.0', reference: '0.7-6woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xzgv is vulnerable in Debian woody.\nUpgrade to xzgv_0.7-6woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
