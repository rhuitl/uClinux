# This script was automatically generated from the dsa-512
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in gallery, a web-based photo album
written in php, whereby a remote attacker could gain access to the
gallery "admin" user without proper authentication.  No CVE candidate
was available for this vulnerability at the time of release.
For the current stable distribution (woody), these problems have been
fixed in version 1.2.5-8woody2.
For the unstable distribution (sid), these problems have been fixed in
version 1.4.3-pl2-1.
We recommend that you update your gallery package.


Solution : http://www.debian.org/security/2004/dsa-512
Risk factor : High';

if (description) {
 script_id(15349);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "512");
 script_cve_id("CVE-2004-0522");
 script_bugtraq_id(10451);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA512] DSA-512-1 gallery");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-512-1 gallery");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian 3.0.\nUpgrade to gallery_1.2.5-8woody2\n');
}
if (deb_check(prefix: 'gallery', release: '3.1', reference: '1.4.3-pl2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian 3.1.\nUpgrade to gallery_1.4.3-pl2-1\n');
}
if (deb_check(prefix: 'gallery', release: '3.0', reference: '1.2.5-8woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gallery is vulnerable in Debian woody.\nUpgrade to gallery_1.2.5-8woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
