# This script was automatically generated from the dsa-642
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in gallery, a web-based
photo album written in PHP4.  The Common Vulnerabilities and Exposures
project identifies the following vulnerabilities:
    Jim Paris discovered a cross site scripting vulnerability which
    allows code to be inserted by using specially formed URLs.
    The upstream developers of gallery have fixed several cases of
    possible variable injection that could trick gallery to unintended
    actions, e.g. leaking database passwords.
For the stable distribution (woody) these problems have been fixed in
version 1.2.5-8woody3.
For the unstable distribution (sid) these problems have been fixed in
version 1.4.4-pl4-1.
We recommend that you upgrade your gallery package.


Solution : http://www.debian.org/security/2005/dsa-642
Risk factor : High';

if (description) {
 script_id(16182);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "642");
 script_cve_id("CVE-2004-1106");
 script_bugtraq_id(11602);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA642] DSA-642-1 gallery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-642-1 gallery");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-8woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian 3.0.\nUpgrade to gallery_1.2.5-8woody3\n');
}
if (deb_check(prefix: 'gallery', release: '3.1', reference: '1.4.4-pl4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian 3.1.\nUpgrade to gallery_1.4.4-pl4-1\n');
}
if (deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-8woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian woody.\nUpgrade to gallery_1.2.5-8woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
