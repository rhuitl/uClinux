# This script was automatically generated from the dsa-796
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Kevin Finisterre reports that affix, a package used to manage
bluetooth sessions under Linux, uses the popen call in an unsafe
fashion. A remote attacker can exploit this vulnerability to execute
arbitrary commands on a vulnerable system.
The old stable distribution (woody) does not contain the affix
package.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.1-3.
For the unstable distribution (sid) this problem has been fixed in
version 2.1.2-3.
We recommend that you upgrade your affix package.


Solution : http://www.debian.org/security/2005/dsa-796
Risk factor : High';

if (description) {
 script_id(19566);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "796");
 script_cve_id("CVE-2005-2716");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA796] DSA-796-1 affix");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-796-1 affix");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'affix', release: '', reference: '2.1.2-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package affix is vulnerable in Debian .\nUpgrade to affix_2.1.2-3\n');
}
if (deb_check(prefix: 'affix', release: '3.1', reference: '2.1.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package affix is vulnerable in Debian 3.1.\nUpgrade to affix_2.1.1-3\n');
}
if (deb_check(prefix: 'libaffix-dev', release: '3.1', reference: '2.1.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libaffix-dev is vulnerable in Debian 3.1.\nUpgrade to libaffix-dev_2.1.1-3\n');
}
if (deb_check(prefix: 'libaffix2', release: '3.1', reference: '2.1.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libaffix2 is vulnerable in Debian 3.1.\nUpgrade to libaffix2_2.1.1-3\n');
}
if (deb_check(prefix: 'affix', release: '3.1', reference: '2.1.1-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package affix is vulnerable in Debian sarge.\nUpgrade to affix_2.1.1-3\n');
}
if (w) { security_hole(port: 0, data: desc); }
