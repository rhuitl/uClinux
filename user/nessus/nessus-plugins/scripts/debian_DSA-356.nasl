# This script was automatically generated from the dsa-356
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered two buffer overflows in xtokkaetama, a puzzle
game, when processing the -display command line option and the
XTOKKAETAMADIR environment variable.  These vulnerabilities could be
exploited by a local attacker to gain gid \'games\'.
For the current stable distribution (woody) this problem has been fixed
in version 1.0b-6woody1.
For the unstable distribution (sid) this problem is fixed in version
1.0b-8.
We recommend that you update your xtokkaetama package.


Solution : http://www.debian.org/security/2003/dsa-356
Risk factor : High';

if (description) {
 script_id(15193);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "356");
 script_cve_id("CVE-2003-0611");
 script_bugtraq_id(8312);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA356] DSA-356-1 xtokkaetama");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-356-1 xtokkaetama");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xtokkaetama', release: '3.0', reference: '1.0b-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xtokkaetama is vulnerable in Debian 3.0.\nUpgrade to xtokkaetama_1.0b-6woody1\n');
}
if (deb_check(prefix: 'xtokkaetama', release: '3.1', reference: '1.0b-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xtokkaetama is vulnerable in Debian 3.1.\nUpgrade to xtokkaetama_1.0b-8\n');
}
if (deb_check(prefix: 'xtokkaetama', release: '3.0', reference: '1.0b-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xtokkaetama is vulnerable in Debian woody.\nUpgrade to xtokkaetama_1.0b-6woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
