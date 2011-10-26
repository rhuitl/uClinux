# This script was automatically generated from the dsa-609
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Adam Zabrocki discovered multiple buffer overflows in atari800, an
Atari emulator.  In order to directly access graphics hardware, one of
the affected programs is installed setuid root.  A local attacker
could exploit this vulnerability to gain root privileges.
For the stable distribution (woody) these problems have been fixed in
version 1.2.2-1woody3.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you upgrade your atari800 package immediately.


Solution : http://www.debian.org/security/2004/dsa-609
Risk factor : High';

if (description) {
 script_id(15961);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "609");
 script_cve_id("CVE-2004-1076");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA609] DSA-609-1 atari800");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-609-1 atari800");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'atari800', release: '3.0', reference: '1.2.2-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package atari800 is vulnerable in Debian 3.0.\nUpgrade to atari800_1.2.2-1woody3\n');
}
if (deb_check(prefix: 'atari800', release: '3.0', reference: '1.2.2-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package atari800 is vulnerable in Debian woody.\nUpgrade to atari800_1.2.2-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
