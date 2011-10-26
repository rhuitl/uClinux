# This script was automatically generated from the dsa-166
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two buffer overflows have been discovered in purity, a game for nerds
and hackers, which is installed setgid games on a Debian system.  This
problem could be exploited to gain unauthorized access to the group
games.  A malicious user could alter the highscore of several games.
This problem has been fixed in version 1-14.2 for the current stable
distribution (woody), in version 1-9.1 for the old stable distribution
(potato) and in version 1-16 for the unstable distribution (sid).
We recommend that you upgrade your purity packages.


Solution : http://www.debian.org/security/2002/dsa-166
Risk factor : High';

if (description) {
 script_id(15003);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "166");
 script_cve_id("CVE-2002-1124");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA166] DSA-166-1 purity");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-166-1 purity");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'purity', release: '2.2', reference: '1-9.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package purity is vulnerable in Debian 2.2.\nUpgrade to purity_1-9.1\n');
}
if (deb_check(prefix: 'purity', release: '3.0', reference: '1-14.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package purity is vulnerable in Debian 3.0.\nUpgrade to purity_1-14.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
