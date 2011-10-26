# This script was automatically generated from the dsa-972
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
SuSE researchers discovered heap overflow errors in xpdf, the Portable
Document Format (PDF) suite, which is also present in
pdfkit.framework, the GNUstep framework for rendering PDF content, and
which can allow attackers to cause a denial of service by crashing the
application or possibly execute arbitrary code.
The old stable distribution (woody) does not contain pdfkit.framework
packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.8-2sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 0.8-4 by switching to poppler.
We recommend that you upgrade your pdfkit.framework package.


Solution : http://www.debian.org/security/2006/dsa-972
Risk factor : High';

if (description) {
 script_id(22838);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "972");
 script_cve_id("CVE-2006-0301");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA972] DSA-972-1 pdfkit.framework");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-972-1 pdfkit.framework");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pdfkit.framework', release: '', reference: '0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdfkit.framework is vulnerable in Debian .\nUpgrade to pdfkit.framework_0\n');
}
if (deb_check(prefix: 'pdfkit.framework', release: '3.1', reference: '0.8-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdfkit.framework is vulnerable in Debian 3.1.\nUpgrade to pdfkit.framework_0.8-2sarge2\n');
}
if (deb_check(prefix: 'pdfkit.framework', release: '3.1', reference: '0.8-2sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdfkit.framework is vulnerable in Debian sarge.\nUpgrade to pdfkit.framework_0.8-2sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
