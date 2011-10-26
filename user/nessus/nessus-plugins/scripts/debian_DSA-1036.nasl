# This script was automatically generated from the dsa-1036
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow problem has been discovered in sail, a game contained
in the bsdgames package, a collection of classic textual Unix games, which
could lead to games group privilege escalation.
For the old stable distribution (woody) this problem has been fixed in
version 2.13-7woody0.
For the stable distribution (sarge) this problem has been fixed in
version 2.17-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.17-7.
We recommend that you upgrade your bsdgames package.


Solution : http://www.debian.org/security/2006/dsa-1036
Risk factor : High';

if (description) {
 script_id(22578);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1036");
 script_cve_id("CVE-2006-1744");
 script_bugtraq_id(17401);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1036] DSA-1036-1 bsdgames");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1036-1 bsdgames");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bsdgames', release: '', reference: '2.17-7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsdgames is vulnerable in Debian .\nUpgrade to bsdgames_2.17-7\n');
}
if (deb_check(prefix: 'bsdgames', release: '3.0', reference: '2.13-7woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsdgames is vulnerable in Debian 3.0.\nUpgrade to bsdgames_2.13-7woody0\n');
}
if (deb_check(prefix: 'bsdgames', release: '3.1', reference: '2.17-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsdgames is vulnerable in Debian 3.1.\nUpgrade to bsdgames_2.17-1sarge1\n');
}
if (deb_check(prefix: 'bsdgames', release: '3.1', reference: '2.17-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsdgames is vulnerable in Debian sarge.\nUpgrade to bsdgames_2.17-1sarge1\n');
}
if (deb_check(prefix: 'bsdgames', release: '3.0', reference: '2.13-7woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bsdgames is vulnerable in Debian woody.\nUpgrade to bsdgames_2.13-7woody0\n');
}
if (w) { security_hole(port: 0, data: desc); }
