# This script was automatically generated from the dsa-982
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Derek Noonburg has fixed several potential vulnerabilities in xpdf,
which are also present in gpdf, the Portable Document Format (PDF)
viewer with Gtk bindings.
The old stable distribution (woody) does not contain gpdf packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.8.2-1.2sarge4.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your gpdf package.


Solution : http://www.debian.org/security/2006/dsa-982
Risk factor : High';

if (description) {
 script_id(22848);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "982");
 script_cve_id("CVE-2006-1244");
 script_bugtraq_id(16748);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA982] DSA-982-1 gpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-982-1 gpdf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gpdf', release: '3.1', reference: '2.8.2-1.2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpdf is vulnerable in Debian 3.1.\nUpgrade to gpdf_2.8.2-1.2sarge4\n');
}
if (deb_check(prefix: 'gpdf', release: '3.1', reference: '2.8.2-1.2sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpdf is vulnerable in Debian sarge.\nUpgrade to gpdf_2.8.2-1.2sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
