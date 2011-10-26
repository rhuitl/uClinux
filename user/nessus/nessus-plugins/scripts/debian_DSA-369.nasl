# This script was automatically generated from the dsa-369
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a buffer overflow in zblast-svgalib, when saving
the high score file.  This vulnerability could be exploited by a local
user to gain gid \'games\', if they can achieve a high score.
For the current stable distribution (woody) this problem has been fixed
in version 1.2pre-5woody2.
For the unstable distribution (sid) this problem is fixed in version
1.2.1-7.
We recommend that you update your zblast package.


Solution : http://www.debian.org/security/2003/dsa-369
Risk factor : High';

if (description) {
 script_id(15206);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "369");
 script_cve_id("CVE-2003-0613");
 script_bugtraq_id(7836);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA369] DSA-369-1 zblast");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-369-1 zblast");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zblast-data', release: '3.0', reference: '1.2pre-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zblast-data is vulnerable in Debian 3.0.\nUpgrade to zblast-data_1.2pre-5woody2\n');
}
if (deb_check(prefix: 'zblast-svgalib', release: '3.0', reference: '1.2pre-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zblast-svgalib is vulnerable in Debian 3.0.\nUpgrade to zblast-svgalib_1.2pre-5woody2\n');
}
if (deb_check(prefix: 'zblast-x11', release: '3.0', reference: '1.2pre-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zblast-x11 is vulnerable in Debian 3.0.\nUpgrade to zblast-x11_1.2pre-5woody2\n');
}
if (deb_check(prefix: 'zblast', release: '3.1', reference: '1.2.1-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zblast is vulnerable in Debian 3.1.\nUpgrade to zblast_1.2.1-7\n');
}
if (deb_check(prefix: 'zblast', release: '3.0', reference: '1.2pre-5woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zblast is vulnerable in Debian woody.\nUpgrade to zblast_1.2pre-5woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
