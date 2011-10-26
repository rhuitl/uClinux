# This script was automatically generated from the dsa-937
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" and Chris Evans discovered several heap based buffer overflows in xpdf,
the Portable Document Format (PDF) suite, which is also present in
tetex-bin, the binary files of teTeX, and which can lead to a denial of
service by crashing the application or possibly to the execution of
arbitrary code.
For the old stable distribution (woody) these problems have been fixed in
version 1.0.7+20011202-7.7.
For the stable distribution (sarge) these problems have been fixed in
version 2.0.2-30sarge4.
For the unstable distribution (sid) these problems have been fixed in
version 0.4.3-2 of poppler against which tetex-bin links.
We recommend that you upgrade your tetex-bin package.


Solution : http://www.debian.org/security/2006/dsa-937
Risk factor : High';

if (description) {
 script_id(22803);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "937");
 script_cve_id("CVE-2005-3191", "CVE-2005-3192", "CVE-2005-3624", "CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627", "CVE-2005-3628");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA937] DSA-937-1 tetex-bin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-937-1 tetex-bin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tetex-bin', release: '', reference: '0.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian .\nUpgrade to tetex-bin_0.4\n');
}
if (deb_check(prefix: 'libkpathsea-dev', release: '3.0', reference: '1.0.7+20011202-7.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkpathsea-dev is vulnerable in Debian 3.0.\nUpgrade to libkpathsea-dev_1.0.7+20011202-7.7\n');
}
if (deb_check(prefix: 'libkpathsea3', release: '3.0', reference: '1.0.7+20011202-7.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkpathsea3 is vulnerable in Debian 3.0.\nUpgrade to libkpathsea3_1.0.7+20011202-7.7\n');
}
if (deb_check(prefix: 'tetex-bin', release: '3.0', reference: '1.0.7+20011202-7.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian 3.0.\nUpgrade to tetex-bin_1.0.7+20011202-7.7\n');
}
if (deb_check(prefix: 'libkpathsea-dev', release: '3.1', reference: '2.0.2-30sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkpathsea-dev is vulnerable in Debian 3.1.\nUpgrade to libkpathsea-dev_2.0.2-30sarge4\n');
}
if (deb_check(prefix: 'libkpathsea3', release: '3.1', reference: '2.0.2-30sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkpathsea3 is vulnerable in Debian 3.1.\nUpgrade to libkpathsea3_2.0.2-30sarge4\n');
}
if (deb_check(prefix: 'tetex-bin', release: '3.1', reference: '2.0.2-30sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian 3.1.\nUpgrade to tetex-bin_2.0.2-30sarge4\n');
}
if (deb_check(prefix: 'tetex-bin', release: '3.1', reference: '2.0.2-30sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian sarge.\nUpgrade to tetex-bin_2.0.2-30sarge4\n');
}
if (deb_check(prefix: 'tetex-bin', release: '3.0', reference: '1.0.7+20011202-7.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian woody.\nUpgrade to tetex-bin_1.0.7+20011202-7.7\n');
}
if (w) { security_hole(port: 0, data: desc); }
