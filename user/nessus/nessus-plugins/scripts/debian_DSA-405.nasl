# This script was automatically generated from the dsa-405
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a problem in xsok, a single player strategy game
for X11, related to the Sokoban game, which leads a user to execute
arbitrary commands under the GID of games.
For the stable distribution (woody) this problem has been fixed in
version 1.02-9woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.02-11.
We recommend that you upgrade your xsok package.


Solution : http://www.debian.org/security/2003/dsa-405
Risk factor : High';

if (description) {
 script_id(15242);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "405");
 script_cve_id("CVE-2003-0949");
 script_bugtraq_id(9321);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA405] DSA-405-1 xsok");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-405-1 xsok");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xsok', release: '3.0', reference: '1.02-9woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xsok is vulnerable in Debian 3.0.\nUpgrade to xsok_1.02-9woody2\n');
}
if (deb_check(prefix: 'xsok', release: '3.1', reference: '1.02-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xsok is vulnerable in Debian 3.1.\nUpgrade to xsok_1.02-11\n');
}
if (deb_check(prefix: 'xsok', release: '3.0', reference: '1.02-9woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xsok is vulnerable in Debian woody.\nUpgrade to xsok_1.02-9woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
