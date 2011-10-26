# This script was automatically generated from the dsa-445
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project 
discovered a vulnerability in
lbreakout2, a game, where proper bounds checking was not performed on
environment variables.  This bug could be exploited by a local
attacker to gain the privileges of group "games".
For the current stable distribution (woody) this problem has been
fixed in version 2.2.2-1woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your lbreakout2 package.


Solution : http://www.debian.org/security/2004/dsa-445
Risk factor : High';

if (description) {
 script_id(15282);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "445");
 script_cve_id("CVE-2004-0158");
 script_bugtraq_id(9712);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA445] DSA-445-1 lbreakout2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-445-1 lbreakout2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lbreakout2', release: '3.0', reference: '2.2.2-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lbreakout2 is vulnerable in Debian 3.0.\nUpgrade to lbreakout2_2.2.2-1woody1\n');
}
if (deb_check(prefix: 'lbreakout2', release: '3.0', reference: '2.2.2-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lbreakout2 is vulnerable in Debian woody.\nUpgrade to lbreakout2_2.2.2-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
