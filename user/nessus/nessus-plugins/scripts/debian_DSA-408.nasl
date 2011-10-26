# This script was automatically generated from the dsa-408
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Timo Sirainen reported a vulnerability in screen, a terminal
multiplexor with VT100/ANSI terminal emulation, that can lead an
attacker to gain group utmp privileges.
For the stable distribution (woody) this problem has been fixed in
version 3.9.11-5woody1.
For the unstable distribution (sid) this problem has been fixed in
version 4.0.2-0.1.
We recommend that you upgrade your screen package.


Solution : http://www.debian.org/security/2004/dsa-408
Risk factor : High';

if (description) {
 script_id(15245);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "408");
 script_cve_id("CVE-2003-0972");
 script_bugtraq_id(9117);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA408] DSA-408-1 screen");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-408-1 screen");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'screen', release: '3.0', reference: '3.9.11-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package screen is vulnerable in Debian 3.0.\nUpgrade to screen_3.9.11-5woody1\n');
}
if (deb_check(prefix: 'screen', release: '3.1', reference: '4.0.2-0.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package screen is vulnerable in Debian 3.1.\nUpgrade to screen_4.0.2-0.1\n');
}
if (deb_check(prefix: 'screen', release: '3.0', reference: '3.9.11-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package screen is vulnerable in Debian woody.\nUpgrade to screen_3.9.11-5woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
