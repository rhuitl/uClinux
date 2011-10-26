# This script was automatically generated from the dsa-400
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a buffer overflow in the commandline and
environment variable handling of omega-rpg, a text-based rogue-style
game of dungeon exploration, which could lead a local attacker to gain
unauthorised access to the group games.
For the stable distribution (woody) this problem has been fixed in
version 0.90-pa9-7woody1.
For the unstable distribution (sid) this problem has been fixed in
version 0.90-pa9-11.
We recommend that you upgrade your omega-rpg package.


Solution : http://www.debian.org/security/2003/dsa-400
Risk factor : High';

if (description) {
 script_id(15237);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "400");
 script_cve_id("CVE-2003-0932");
 script_bugtraq_id(9016);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA400] DSA-400-1 omega-rpg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-400-1 omega-rpg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'omega-rpg', release: '3.0', reference: '0.90-pa9-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package omega-rpg is vulnerable in Debian 3.0.\nUpgrade to omega-rpg_0.90-pa9-7woody1\n');
}
if (deb_check(prefix: 'omega-rpg', release: '3.1', reference: '0.90-pa9-11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package omega-rpg is vulnerable in Debian 3.1.\nUpgrade to omega-rpg_0.90-pa9-11\n');
}
if (deb_check(prefix: 'omega-rpg', release: '3.0', reference: '0.90-pa9-7woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package omega-rpg is vulnerable in Debian woody.\nUpgrade to omega-rpg_0.90-pa9-7woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
