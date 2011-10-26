# This script was automatically generated from the dsa-1106
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcus Meissner discovered that the winbind plugin in pppd does not
check whether a setuid() call has been successful when trying to drop
privileges, which may fail with some PAM configurations.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.4.3-20050321+2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.4.4rel-1.
We recommend that you upgrade your ppp package.


Solution : http://www.debian.org/security/2006/dsa-1106
Risk factor : High';

if (description) {
 script_id(22648);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1106");
 script_cve_id("CVE-2006-2194");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1106] DSA-1106-1 ppp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1106-1 ppp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ppp', release: '', reference: '2.4.4rel-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppp is vulnerable in Debian .\nUpgrade to ppp_2.4.4rel-1\n');
}
if (deb_check(prefix: 'ppp', release: '3.1', reference: '2.4.3-20050321+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppp is vulnerable in Debian 3.1.\nUpgrade to ppp_2.4.3-20050321+2sarge1\n');
}
if (deb_check(prefix: 'ppp-dev', release: '3.1', reference: '2.4.3-20050321+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppp-dev is vulnerable in Debian 3.1.\nUpgrade to ppp-dev_2.4.3-20050321+2sarge1\n');
}
if (deb_check(prefix: 'ppp', release: '3.1', reference: '2.4.3-20050321+2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ppp is vulnerable in Debian sarge.\nUpgrade to ppp_2.4.3-20050321+2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
