# This script was automatically generated from the dsa-644
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Danny Lungstrom discovered a vulnerability in chbg, a tool to change
background pictures.  A maliciously crafted configuration/scenario
file could overflow a buffer and lead to the execution of arbitrary
code on the victim\'s machine.
For the stable distribution (woody) this problem has been fixed in
version 1.5-1woody1.
For the unstable distribution (sid) this problem has been fixed in
version 1.5-4.
We recommend that you upgrade your chbg package.


Solution : http://www.debian.org/security/2005/dsa-644
Risk factor : High';

if (description) {
 script_id(16186);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "644");
 script_cve_id("CVE-2004-1264");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA644] DSA-644-1 chbg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-644-1 chbg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'chbg', release: '3.0', reference: '1.5-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chbg is vulnerable in Debian 3.0.\nUpgrade to chbg_1.5-1woody1\n');
}
if (deb_check(prefix: 'chbg', release: '3.1', reference: '1.5-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chbg is vulnerable in Debian 3.1.\nUpgrade to chbg_1.5-4\n');
}
if (deb_check(prefix: 'chbg', release: '3.0', reference: '1.5-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package chbg is vulnerable in Debian woody.\nUpgrade to chbg_1.5-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
