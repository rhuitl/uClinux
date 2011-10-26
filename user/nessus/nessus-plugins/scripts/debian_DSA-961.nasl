# This script was automatically generated from the dsa-961
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '

"infamous41md" and Chris Evans discovered several heap based buffer
overflows in xpdf which are also present in pdfkit.framework, the
GNUstep framework for rendering PDF content, and which can lead to a
denial of service by crashing the application or possibly to the
execution of arbitrary code.
The old stable distribution (woody) does not contain pdfkit.framework
packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.8-2sarge1.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your pdfkit.framework package.


Solution : http://www.debian.org/security/2006/dsa-961
Risk factor : High';

if (description) {
 script_id(22827);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "961");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3193", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA961] DSA-961-1 pdfkit.framework");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-961-1 pdfkit.framework");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pdfkit.framework', release: '3.1', reference: '0.8-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdfkit.framework is vulnerable in Debian 3.1.\nUpgrade to pdfkit.framework_0.8-2sarge1\n');
}
if (deb_check(prefix: 'pdfkit.framework', release: '3.1', reference: '0.8-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pdfkit.framework is vulnerable in Debian sarge.\nUpgrade to pdfkit.framework_0.8-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
