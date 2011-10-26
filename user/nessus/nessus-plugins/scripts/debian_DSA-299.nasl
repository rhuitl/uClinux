# This script was automatically generated from the dsa-299
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Maurice Massar discovered that, due to a packaging error, the program
/usr/bin/KATAXWR was inadvertently installed setuid root.  This
program was not designed to run setuid, and contained multiple
vulnerabilities which could be exploited to gain root privileges.
For the stable distribution (woody) this problem has been fixed in
version 1.2-3.1.
The old stable distribution (potato) does not contain a leksbot
package.
For the unstable distribution (sid) this problem has been fixed in
version 1.2-5.
We recommend that you update your leksbot package.


Solution : http://www.debian.org/security/2003/dsa-299
Risk factor : High';

if (description) {
 script_id(15136);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "299");
 script_cve_id("CVE-2003-0262");
 script_bugtraq_id(7505);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA299] DSA-299-1 leksbot");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-299-1 leksbot");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'leksbot', release: '3.0', reference: '1.2-3.1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package leksbot is vulnerable in Debian 3.0.\nUpgrade to leksbot_1.2-3.1woody1\n');
}
if (deb_check(prefix: 'leksbot', release: '3.1', reference: '1.2-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package leksbot is vulnerable in Debian 3.1.\nUpgrade to leksbot_1.2-5\n');
}
if (deb_check(prefix: 'leksbot', release: '3.0', reference: '1.2-3.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package leksbot is vulnerable in Debian woody.\nUpgrade to leksbot_1.2-3.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
