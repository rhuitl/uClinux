# This script was automatically generated from the dsa-684
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered a
problem in typespeed, a touch-typist trainer disguised as game.  This
could lead to a local attacker executing arbitrary code as group
games.
For the stable distribution (woody) this problem has been fixed in
version 0.4.1-2.3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your typespeed package.


Solution : http://www.debian.org/security/2005/dsa-684
Risk factor : High';

if (description) {
 script_id(16470);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "684");
 script_cve_id("CVE-2005-0105");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA684] DSA-684-1 typespeed");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-684-1 typespeed");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian 3.0.\nUpgrade to typespeed_0.4.1-2.3\n');
}
if (deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian woody.\nUpgrade to typespeed_0.4.1-2.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
