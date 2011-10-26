# This script was automatically generated from the dsa-359
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered multiple buffer overflows in atari800, an Atari
emulator.  In order to directly access graphics hardware, one of the
affected programs is setuid root.  A local attacker could exploit this
vulnerability to gain root privileges.
For the current stable distribution (woody) this problem has been fixed
in version 1.2.2-1woody2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you update your atari800 package.


Solution : http://www.debian.org/security/2003/dsa-359
Risk factor : High';

if (description) {
 script_id(15196);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "359");
 script_cve_id("CVE-2003-0630");
 script_bugtraq_id(8322);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA359] DSA-359-1 atari800");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-359-1 atari800");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'atari800', release: '3.0', reference: '1.2.2-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package atari800 is vulnerable in Debian 3.0.\nUpgrade to atari800_1.2.2-1woody2\n');
}
if (deb_check(prefix: 'atari800', release: '3.0', reference: '1.2.2-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package atari800 is vulnerable in Debian woody.\nUpgrade to atari800_1.2.2-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
