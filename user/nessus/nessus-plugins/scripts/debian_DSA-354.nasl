# This script was automatically generated from the dsa-354
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a buffer overflow in xconq, in processing the
USER environment variable.  In the process of fixing this bug, a
similar problem was discovered with the DISPLAY environment
variable.  This vulnerability could be exploited by a local attacker
to gain gid \'games\'.
For the current stable distribution (woody) this problem has been fixed
in version 7.4.1-2woody2.
For the unstable distribution (sid) this problem will be fixed soon.
Refer to Debian bug #202963.
We recommend that you update your xconq package.


Solution : http://www.debian.org/security/2003/dsa-354
Risk factor : High';

if (description) {
 script_id(15191);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "354");
 script_cve_id("CVE-2003-0607");
 script_bugtraq_id(8307);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA354] DSA-354-1 xconq");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-354-1 xconq");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xconq', release: '3.0', reference: '7.4.1-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xconq is vulnerable in Debian 3.0.\nUpgrade to xconq_7.4.1-2woody2\n');
}
if (deb_check(prefix: 'xconq-common', release: '3.0', reference: '7.4.1-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xconq-common is vulnerable in Debian 3.0.\nUpgrade to xconq-common_7.4.1-2woody2\n');
}
if (deb_check(prefix: 'xconq-doc', release: '3.0', reference: '7.4.1-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xconq-doc is vulnerable in Debian 3.0.\nUpgrade to xconq-doc_7.4.1-2woody2\n');
}
if (deb_check(prefix: 'xconq', release: '3.0', reference: '7.4.1-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xconq is vulnerable in Debian woody.\nUpgrade to xconq_7.4.1-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
