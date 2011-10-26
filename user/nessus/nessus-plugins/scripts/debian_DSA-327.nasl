# This script was automatically generated from the dsa-327
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered several buffer overflows in xbl, a game, which
can be triggered by long command line arguments.  This vulnerability
could be exploited by a local attacker to gain gid \'games\'.
For the stable distribution (woody) this problem has been fixed in
version 1.0k-3woody1.
For the old stable distribution (potato) this problem has been fixed
in version 1.0i-7potato1.
For the unstable distribution (sid) this problem is fixed in version
1.0k-5.
We recommend that you update your xbl package.


Solution : http://www.debian.org/security/2003/dsa-327
Risk factor : High';

if (description) {
 script_id(15164);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "327");
 script_cve_id("CVE-2003-0451");
 script_bugtraq_id(7989);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA327] DSA-327-1 xbl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-327-1 xbl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xbl', release: '2.2', reference: '1.0i-7potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xbl is vulnerable in Debian 2.2.\nUpgrade to xbl_1.0i-7potato1\n');
}
if (deb_check(prefix: 'xbl', release: '3.0', reference: '1.0k-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xbl is vulnerable in Debian 3.0.\nUpgrade to xbl_1.0k-3woody1\n');
}
if (deb_check(prefix: 'xbl', release: '3.1', reference: '1.0k-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xbl is vulnerable in Debian 3.1.\nUpgrade to xbl_1.0k-5\n');
}
if (deb_check(prefix: 'xbl', release: '2.2', reference: '1.0i-7potato1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xbl is vulnerable in Debian potato.\nUpgrade to xbl_1.0i-7potato1\n');
}
if (deb_check(prefix: 'xbl', release: '3.0', reference: '1.0k-3woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xbl is vulnerable in Debian woody.\nUpgrade to xbl_1.0k-3woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
