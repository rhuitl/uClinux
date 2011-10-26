# This script was automatically generated from the dsa-1066
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It was discovered that phpbb2, a web based bulletin board, does
insufficiently sanitise values passed to the "Font Colour 3" setting,
which might lead to the execution of injected code by admin users.
The old stable distribution (woody) does not contain phpbb2 packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.13+1-6sarge3.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your phpbb2 package.


Solution : http://www.debian.org/security/2006/dsa-1066
Risk factor : High';

if (description) {
 script_id(22608);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1066");
 script_cve_id("CVE-2006-1896");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1066] DSA-1066-1 phpbb2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1066-1 phpbb2");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2 is vulnerable in Debian 3.1.\nUpgrade to phpbb2_2.0.13-6sarge3\n');
}
if (deb_check(prefix: 'phpbb2-conf-mysql', release: '3.1', reference: '2.0.13-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2-conf-mysql is vulnerable in Debian 3.1.\nUpgrade to phpbb2-conf-mysql_2.0.13-6sarge3\n');
}
if (deb_check(prefix: 'phpbb2-languages', release: '3.1', reference: '2.0.13-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2-languages is vulnerable in Debian 3.1.\nUpgrade to phpbb2-languages_2.0.13-6sarge3\n');
}
if (deb_check(prefix: 'phpbb2', release: '3.1', reference: '2.0.13+1-6sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package phpbb2 is vulnerable in Debian sarge.\nUpgrade to phpbb2_2.0.13+1-6sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
