# This script was automatically generated from the dsa-1136
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
<q>infamous41md</q> and Chris Evans discovered several heap based buffer
overflows in xpdf, the Portable Document Format (PDF) suite, which are
also present in gpdf, the viewer with Gtk bindings, and which can lead
to a denial of service by crashing the application or possibly to the
execution of arbitrary code.
For the stable distribution (sarge) these problems have been fixed in
version 2.8.2-1.2sarge5.
For the unstable distribution (sid) these problems have been fixed in
version 2.10.0-4.
We recommend that you upgrade your gpdf package.


Solution : http://www.debian.org/security/2006/dsa-1136
Risk factor : High';

if (description) {
 script_id(22678);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1136");
 script_cve_id("CVE-2005-2097");
 script_bugtraq_id(14529);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1136] DSA-1136-1 gpdf");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1136-1 gpdf");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gpdf', release: '', reference: '2.10.0-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpdf is vulnerable in Debian .\nUpgrade to gpdf_2.10.0-4\n');
}
if (deb_check(prefix: 'gpdf', release: '3.1', reference: '2.8.2-1.2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpdf is vulnerable in Debian 3.1.\nUpgrade to gpdf_2.8.2-1.2sarge5\n');
}
if (deb_check(prefix: 'gpdf', release: '3.1', reference: '2.8.2-1.2sarge5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gpdf is vulnerable in Debian sarge.\nUpgrade to gpdf_2.8.2-1.2sarge5\n');
}
if (w) { security_hole(port: 0, data: desc); }
