# This script was automatically generated from the dsa-398
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered a buffer overflow in the environment variable
handling of conquest, a curses based, real-time, multi-player space
warfare game, which could lead a local attacker to gain unauthorised
access to the group conquest.
For the stable distribution (woody) this problem has been fixed in
version 7.1.1-6woody1.
For the unstable distribution (sid) this problem has been fixed in
version 7.2-5.
We recommend that you upgrade your conquest package.


Solution : http://www.debian.org/security/2003/dsa-398
Risk factor : High';

if (description) {
 script_id(15235);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "398");
 script_cve_id("CVE-2003-0933");
 script_bugtraq_id(8996);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA398] DSA-398-1 conquest");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-398-1 conquest");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'conquest', release: '3.0', reference: '7.1.1-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package conquest is vulnerable in Debian 3.0.\nUpgrade to conquest_7.1.1-6woody1\n');
}
if (deb_check(prefix: 'conquest', release: '3.1', reference: '7.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package conquest is vulnerable in Debian 3.1.\nUpgrade to conquest_7.2-5\n');
}
if (deb_check(prefix: 'conquest', release: '3.0', reference: '7.1.1-6woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package conquest is vulnerable in Debian woody.\nUpgrade to conquest_7.1.1-6woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
