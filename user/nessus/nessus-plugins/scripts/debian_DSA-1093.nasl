# This script was automatically generated from the dsa-1093
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several format string vulnerabilities have been discovered in xine-ui,
the user interface of the xine video player, which may cause a denial
of service.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 0.99.3-1sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your xine-ui package.


Solution : http://www.debian.org/security/2006/dsa-1093
Risk factor : High';

if (description) {
 script_id(22635);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1093");
 script_cve_id("CVE-2006-2230");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1093] DSA-1093-1 xine");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1093-1 xine");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xine-ui', release: '3.1', reference: '0.99.3-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-ui is vulnerable in Debian 3.1.\nUpgrade to xine-ui_0.99.3-1sarge1\n');
}
if (deb_check(prefix: 'xine-ui', release: '3.1', reference: '0.99.3-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xine-ui is vulnerable in Debian sarge.\nUpgrade to xine-ui_0.99.3-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
