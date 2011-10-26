# This script was automatically generated from the dsa-1028
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Kjetil Kjernsmo discovered a bug in libimager-perl, a Perl extension
for generating 24 bit images, which can lead to a segmentation fault
if it operates on 4-channel JPEG images.
The old stable distribution (woody) does not contain this package.
For the stable distribution (sarge) this problem has been fixed in
version 0.44-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.50-1.
We recommend that you upgrade your libimager-perl package.


Solution : http://www.debian.org/security/2006/dsa-1028
Risk factor : High';

if (description) {
 script_id(22570);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1028");
 script_cve_id("CVE-2006-0053");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1028] DSA-1028-1 libimager-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1028-1 libimager-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libimager-perl', release: '', reference: '0.50-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libimager-perl is vulnerable in Debian .\nUpgrade to libimager-perl_0.50-1\n');
}
if (deb_check(prefix: 'libimager-perl', release: '3.1', reference: '0.44-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libimager-perl is vulnerable in Debian 3.1.\nUpgrade to libimager-perl_0.44-1sarge1\n');
}
if (deb_check(prefix: 'libimager-perl', release: '3.1', reference: '0.44-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libimager-perl is vulnerable in Debian sarge.\nUpgrade to libimager-perl_0.44-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
