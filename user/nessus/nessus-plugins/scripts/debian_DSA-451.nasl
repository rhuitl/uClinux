# This script was automatically generated from the dsa-451
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a number of buffer overflow vulnerabilities in
xboing, a game, which could be exploited by a local attacker to gain
gid "games".
For the current stable distribution (woody) these problems have been
fixed in version 2.4-26woody1.
For the unstable distribution (sid), these problems have been fixed in
version 2.4-26.1.
We recommend that you update your xboing package.


Solution : http://www.debian.org/security/2004/dsa-451
Risk factor : High';

if (description) {
 script_id(15288);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "451");
 script_cve_id("CVE-2004-0149");
 script_bugtraq_id(9764);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA451] DSA-451-1 xboing");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-451-1 xboing");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xboing', release: '3.0', reference: '2.4-26woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xboing is vulnerable in Debian 3.0.\nUpgrade to xboing_2.4-26woody1\n');
}
if (deb_check(prefix: 'xboing', release: '3.1', reference: '2.4-26.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xboing is vulnerable in Debian 3.1.\nUpgrade to xboing_2.4-26.1\n');
}
if (deb_check(prefix: 'xboing', release: '3.0', reference: '2.4-26woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xboing is vulnerable in Debian woody.\nUpgrade to xboing_2.4-26woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
