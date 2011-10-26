# This script was automatically generated from the dsa-979
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Derek Noonburg has fixed several potential vulnerabilities in xpdf,
the Portable Document Format (PDF) suite, which are also present in
pdfkit.framework, the GNUstep framework for rendering PDF content.
The old stable distribution (woody) does not contain pdfkit.framework
packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.8-2sarge3.
The unstable distribution (sid) is not affected by these problems.
We recommend that you upgrade your pdfkit.framework package.


Solution : http://www.debian.org/security/2006/dsa-979
Risk factor : High';

if (description) {
 script_id(22845);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "979");
 script_cve_id("CVE-2006-1244");
 script_bugtraq_id(16748);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA979] DSA-979-1 pdfkit.framework");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-979-1 pdfkit.framework");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pdfkit.framework', release: '3.1', reference: '0.8-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdfkit.framework is vulnerable in Debian 3.1.\nUpgrade to pdfkit.framework_0.8-2sarge3\n');
}
if (deb_check(prefix: 'pdfkit.framework', release: '3.1', reference: '0.8-2sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdfkit.framework is vulnerable in Debian sarge.\nUpgrade to pdfkit.framework_0.8-2sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
