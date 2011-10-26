# This script was automatically generated from the dsa-217
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in the typespeed, a game that lets you
measure your typematic speed.  By overflowing a buffer  a local
attacker could execute arbitrary commands under the group id games.
For the current stable distribution (woody) this problem has been
fixed in version 0.4.1-2.1.
For the old stable distribution (potato) this problem has been fixed
in version 0.4.0-5.1.
For the unstable distribution (sid) this problem has been fixed in
version 0.4.2-2.
We recommend that you upgrade your typespeed package.


Solution : http://www.debian.org/security/2002/dsa-217
Risk factor : High';

if (description) {
 script_id(15054);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "217");
 script_cve_id("CVE-2002-1389");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA217] DSA-217-1 typespeed");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-217-1 typespeed");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'typespeed', release: '2.2', reference: '0.4.0-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian 2.2.\nUpgrade to typespeed_0.4.0-5.1\n');
}
if (deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian 3.0.\nUpgrade to typespeed_0.4.1-2.1\n');
}
if (deb_check(prefix: 'typespeed', release: '3.1', reference: '0.4.2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian 3.1.\nUpgrade to typespeed_0.4.2-2\n');
}
if (deb_check(prefix: 'typespeed', release: '2.2', reference: '0.4.0-5.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian potato.\nUpgrade to typespeed_0.4.0-5.1\n');
}
if (deb_check(prefix: 'typespeed', release: '3.0', reference: '0.4.1-2.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package typespeed is vulnerable in Debian woody.\nUpgrade to typespeed_0.4.1-2.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
