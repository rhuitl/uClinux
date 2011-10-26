# This script was automatically generated from the dsa-207
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The SuSE security team discovered a vulnerability in kpathsea library
(libkpathsea) which is used by xdvi and dvips.  Both programs call the
system() function insecurely, which allows a remote attacker to
execute arbitrary commands via cleverly crafted DVI files.
If dvips is used in a print filter, this allows a local or remote
attacker with print permission execute arbitrary code as the printer
user (usually lp).
This problem has been fixed in version 1.0.7+20011202-7.1 for the
current stable distribution (woody), in version 1.0.6-7.3 for the old
stable distribution (potato) and in version 1.0.7+20021025-4 for the
unstable distribution (sid).  xdvik-ja and dvipsk-ja are vulnerable as
well, but link to the kpathsea library dynamically and will
automatically be fixed after a new libkpathsea is installed.
We recommend that you upgrade your tetex-lib package immediately.


Solution : http://www.debian.org/security/2002/dsa-207
Risk factor : High';

if (description) {
 script_id(15044);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "207");
 script_cve_id("CVE-2002-0836");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA207] DSA-207-1 tetex-bin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-207-1 tetex-bin");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tetex-bin', release: '2.2', reference: '1.0.6-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian 2.2.\nUpgrade to tetex-bin_1.0.6-7.3\n');
}
if (deb_check(prefix: 'tetex-dev', release: '2.2', reference: '1.0.6-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-dev is vulnerable in Debian 2.2.\nUpgrade to tetex-dev_1.0.6-7.3\n');
}
if (deb_check(prefix: 'tetex-lib', release: '2.2', reference: '1.0.6-7.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-lib is vulnerable in Debian 2.2.\nUpgrade to tetex-lib_1.0.6-7.3\n');
}
if (deb_check(prefix: 'libkpathsea-dev', release: '3.0', reference: '1.0.7+20011202-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkpathsea-dev is vulnerable in Debian 3.0.\nUpgrade to libkpathsea-dev_1.0.7+20011202-7.1\n');
}
if (deb_check(prefix: 'libkpathsea3', release: '3.0', reference: '1.0.7+20011202-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libkpathsea3 is vulnerable in Debian 3.0.\nUpgrade to libkpathsea3_1.0.7+20011202-7.1\n');
}
if (deb_check(prefix: 'tetex-bin', release: '3.0', reference: '1.0.7+20011202-7.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tetex-bin is vulnerable in Debian 3.0.\nUpgrade to tetex-bin_1.0.7+20011202-7.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
