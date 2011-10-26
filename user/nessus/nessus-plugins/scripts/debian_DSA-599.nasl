# This script was automatically generated from the dsa-599
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Chris Evans discovered several integer overflows in xpdf, that are
also present in tetex-bin, binary files for the teTeX distribution,
which can be exploited remotely by a specially crafted PDF document
and lead to the execution of arbitrary code.
For the stable distribution (woody) these problems have been fixed in
version 20011202-7.3.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.2-23.
We recommend that you upgrade your tetex-bin packages.


Solution : http://www.debian.org/security/2004/dsa-599
Risk factor : High';

if (description) {
 script_id(15835);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "599");
 script_cve_id("CVE-2004-0888");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA599] DSA-599-1 tetex-bin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-599-1 tetex-bin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libkpathsea-dev', release: '3.0', reference: '1.0.7+20011202-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkpathsea-dev is vulnerable in Debian 3.0.\nUpgrade to libkpathsea-dev_1.0.7+20011202-7.3\n');
}
if (deb_check(prefix: 'libkpathsea3', release: '3.0', reference: '1.0.7+20011202-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkpathsea3 is vulnerable in Debian 3.0.\nUpgrade to libkpathsea3_1.0.7+20011202-7.3\n');
}
if (deb_check(prefix: 'tetex-bin', release: '3.0', reference: '1.0.7+20011202-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian 3.0.\nUpgrade to tetex-bin_1.0.7+20011202-7.3\n');
}
if (deb_check(prefix: 'tetex-bin', release: '3.1', reference: '2.0.2-23')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian 3.1.\nUpgrade to tetex-bin_2.0.2-23\n');
}
if (deb_check(prefix: 'tetex-bin', release: '3.0', reference: '20011202-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian woody.\nUpgrade to tetex-bin_20011202-7.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
