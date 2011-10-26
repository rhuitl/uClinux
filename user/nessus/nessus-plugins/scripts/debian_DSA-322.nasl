# This script was automatically generated from the dsa-322
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
typespeed is a game which challenges the player to type words
correctly and quickly.  It contains a network play mode which allows
players on different systems to play competitively.  The network code
contains a buffer overflow which could allow a remote attacker to
execute arbitrary code under the privileges of the user invoking
typespeed, in addition to gid games.
For the stable distribution (woody) this problem has been fixed in
version 0.4.1-2.2.
For the old stable distribution (potato) this problem has been fixed
in version 0.4.0-5.2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your typespeed package.


Solution : http://www.debian.org/security/2003/dsa-322
Risk factor : High';

if (description) {
 script_id(15159);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "322");
 script_cve_id("CVE-2003-0435");
 script_bugtraq_id(7891);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA322] DSA-322-1 typespeed");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-322-1 typespeed");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'typespeed', release: '2.2', reference: '0.4.0-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian 2.2.\nUpgrade to typespeed_0.4.0-5.2\n');
}
if (deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian 3.0.\nUpgrade to typespeed_0.4.1-2.2\n');
}
if (deb_check(prefix: 'typespeed', release: '2.2', reference: '0.4.0-5.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian potato.\nUpgrade to typespeed_0.4.0-5.2\n');
}
if (deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian woody.\nUpgrade to typespeed_0.4.1-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
