# This script was automatically generated from the dsa-430
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a problem in trr19, a type trainer application
for GNU Emacs, which is written as a pair of setgid() binaries and
wrapper programs which execute commands for GNU Emacs.  However, the
binaries don\'t drop privileges before executing a command, allowing an
attacker to gain access to the local group games.
For the stable distribution (woody) this problem has been fixed in
version 1.0beta5-15woody1.  The mipsel binary will be added later.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your trr19 package.


Solution : http://www.debian.org/security/2004/dsa-430
Risk factor : High';

if (description) {
 script_id(15267);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "430");
 script_cve_id("CVE-2004-0047");
 script_bugtraq_id(9520);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA430] DSA-430-1 trr19");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-430-1 trr19");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'trr19', release: '3.0', reference: '1.0beta5-15woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trr19 is vulnerable in Debian 3.0.\nUpgrade to trr19_1.0beta5-15woody1\n');
}
if (deb_check(prefix: 'trr19', release: '3.0', reference: '1.0beta5-15woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package trr19 is vulnerable in Debian woody.\nUpgrade to trr19_1.0beta5-15woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
