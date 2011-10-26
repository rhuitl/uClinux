# This script was automatically generated from the dsa-484
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a vulnerability in xonix, a game, where an
external program was invoked while retaining setgid privileges.  A
local attacker could exploit this vulnerability to gain gid "games".
For the current stable distribution (woody) this problem will be fixed
in version 1.4-19woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your xonix package.


Solution : http://www.debian.org/security/2004/dsa-484
Risk factor : High';

if (description) {
 script_id(15321);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "484");
 script_cve_id("CVE-2004-0157");
 script_bugtraq_id(10149);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA484] DSA-484-1 xonix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-484-1 xonix");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xonix', release: '3.0', reference: '1.4-19woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xonix is vulnerable in Debian 3.0.\nUpgrade to xonix_1.4-19woody1\n');
}
if (deb_check(prefix: 'xonix', release: '3.0', reference: '1.4-19woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xonix is vulnerable in Debian woody.\nUpgrade to xonix_1.4-19woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
