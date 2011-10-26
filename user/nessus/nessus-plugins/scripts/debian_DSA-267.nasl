# This script was automatically generated from the dsa-267
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in lpr, a BSD lpr/lpd line
printer spooling system.  This problem can be exploited by a local
user to gain root privileges, even if the printer system is set up
properly.
For the stable distribution (woody) this problem has been fixed in
version 2000.05.07-4.3.
For the old stable distribution (potato) this problem has been fixed
in version 0.48-1.1.
For the unstable distribution (sid) this problem has been fixed in
version 2000.05.07-4.20.
We recommend that you upgrade your lpr package immediately.


Solution : http://www.debian.org/security/2003/dsa-267
Risk factor : High';

if (description) {
 script_id(15104);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "267");
 script_cve_id("CVE-2003-0144");
 script_bugtraq_id(7025);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA267] DSA-267-1 lpr");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-267-1 lpr");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lpr', release: '2.2', reference: '0.48-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lpr is vulnerable in Debian 2.2.\nUpgrade to lpr_0.48-1.2\n');
}
if (deb_check(prefix: 'lpr', release: '3.0', reference: '2000.05.07-4.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lpr is vulnerable in Debian 3.0.\nUpgrade to lpr_2000.05.07-4.3\n');
}
if (deb_check(prefix: 'lpr', release: '3.1', reference: '2000.05.07-4.20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lpr is vulnerable in Debian 3.1.\nUpgrade to lpr_2000.05.07-4.20\n');
}
if (deb_check(prefix: 'lpr', release: '2.2', reference: '0.48-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lpr is vulnerable in Debian potato.\nUpgrade to lpr_0.48-1.1\n');
}
if (deb_check(prefix: 'lpr', release: '3.0', reference: '2000.05.07-4.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lpr is vulnerable in Debian woody.\nUpgrade to lpr_2000.05.07-4.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
