# This script was automatically generated from the dsa-740
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An error in the way zlib handles the inflation of certain compressed
files can cause a program which uses zlib to crash when opening an
invalid file. 
This problem does not affect the old stable distribution (woody).
For the stable distribution (sarge), this problem has been fixed in
version 1.2.2-4.sarge.1.
For the unstable distribution, this problem has been fixed in version
1.2.2-7.
We recommend that you upgrade your zlib package.


Solution : http://www.debian.org/security/2005/dsa-740
Risk factor : High';

if (description) {
 script_id(18632);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "740");
 script_cve_id("CVE-2005-2096");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA740] DSA-740-1 zlib");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-740-1 zlib");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lib64z1', release: '3.1', reference: '1.2.2-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lib64z1 is vulnerable in Debian 3.1.\nUpgrade to lib64z1_1.2.2-4.sarge.1\n');
}
if (deb_check(prefix: 'lib64z1-dev', release: '3.1', reference: '1.2.2-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lib64z1-dev is vulnerable in Debian 3.1.\nUpgrade to lib64z1-dev_1.2.2-4.sarge.1\n');
}
if (deb_check(prefix: 'zlib-bin', release: '3.1', reference: '1.2.2-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib-bin is vulnerable in Debian 3.1.\nUpgrade to zlib-bin_1.2.2-4.sarge.1\n');
}
if (deb_check(prefix: 'zlib1g', release: '3.1', reference: '1.2.2-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib1g is vulnerable in Debian 3.1.\nUpgrade to zlib1g_1.2.2-4.sarge.1\n');
}
if (deb_check(prefix: 'zlib1g-dev', release: '3.1', reference: '1.2.2-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib1g-dev is vulnerable in Debian 3.1.\nUpgrade to zlib1g-dev_1.2.2-4.sarge.1\n');
}
if (deb_check(prefix: 'zlib', release: '3.1', reference: '1.2.2-4.sarge.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zlib is vulnerable in Debian sarge.\nUpgrade to zlib_1.2.2-4.sarge.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
