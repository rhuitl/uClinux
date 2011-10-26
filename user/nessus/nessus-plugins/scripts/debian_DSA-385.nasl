# This script was automatically generated from the dsa-385
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jens Steube reported a pair of buffer overflow vulnerabilities in
hztty, a program to translate Chinese character encodings in a
terminal session.  These vulnerabilities could be exploited by a local
attacker to gain root privileges on a system where hztty is installed.
Additionally, hztty had been incorrectly installed setuid root, when
it only requires the privileges of group utmp.  This has also been
corrected in this update.
For the stable distribution (woody) this problem has been fixed in
version 2.0-5.2woody1.
For the unstable distribution (sid) this problem will be fixed in
version 2.0-6.
We recommend that you update your hztty package.


Solution : http://www.debian.org/security/2003/dsa-385
Risk factor : High';

if (description) {
 script_id(15222);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "385");
 script_cve_id("CVE-2003-0783");
 script_bugtraq_id(8656);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA385] DSA-385-1 hztty");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-385-1 hztty");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'hztty', release: '3.0', reference: '2.0-5.2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hztty is vulnerable in Debian 3.0.\nUpgrade to hztty_2.0-5.2woody1\n');
}
if (deb_check(prefix: 'hztty', release: '3.1', reference: '2.0-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hztty is vulnerable in Debian 3.1.\nUpgrade to hztty_2.0-6\n');
}
if (deb_check(prefix: 'hztty', release: '3.0', reference: '2.0-5.2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package hztty is vulnerable in Debian woody.\nUpgrade to hztty_2.0-5.2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
