# This script was automatically generated from the dsa-858
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ariel Berkman discovered several buffer overflows in xloadimage, a
graphics file viewer for X11, that can be exploited via large image
titles and cause the execution of arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 4.1-10woody2.
For the stable distribution (sarge) these problems have been fixed in
version 4.1-14.3.
For the unstable distribution (sid) these problems have been fixed in
version 4.1-15.
We recommend that you upgrade your xloadimage package.


Solution : http://www.debian.org/security/2005/dsa-858
Risk factor : High';

if (description) {
 script_id(19966);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "858");
 script_cve_id("CVE-2005-3178");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA858] DSA-858-1 xloadimage");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-858-1 xloadimage");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xloadimage', release: '', reference: '4.1-15')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xloadimage is vulnerable in Debian .\nUpgrade to xloadimage_4.1-15\n');
}
if (deb_check(prefix: 'xloadimage', release: '3.0', reference: '4.1-10woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xloadimage is vulnerable in Debian 3.0.\nUpgrade to xloadimage_4.1-10woody2\n');
}
if (deb_check(prefix: 'xloadimage', release: '3.1', reference: '4.1-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xloadimage is vulnerable in Debian 3.1.\nUpgrade to xloadimage_4.1-14.3\n');
}
if (deb_check(prefix: 'xloadimage', release: '3.1', reference: '4.1-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xloadimage is vulnerable in Debian sarge.\nUpgrade to xloadimage_4.1-14.3\n');
}
if (deb_check(prefix: 'xloadimage', release: '3.0', reference: '4.1-10woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xloadimage is vulnerable in Debian woody.\nUpgrade to xloadimage_4.1-10woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
