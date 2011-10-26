# This script was automatically generated from the dsa-610
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in cscope, a program to
interactively examine C source code, which may allow local users to
overwrite files via a symlink attack.
For the stable distribution (woody) this problem has been fixed in
version 15.3-1woody2.
For the unstable distribution (sid) this problem has been fixed in
version 15.5-1.
We recommend that you upgrade your cscope package.


Solution : http://www.debian.org/security/2004/dsa-610
Risk factor : High';

if (description) {
 script_id(15994);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "610");
 script_cve_id("CVE-2004-0996");
 script_bugtraq_id(11697);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA610] DSA-610-1 cscope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-610-1 cscope");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cscope', release: '3.0', reference: '15.3-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian 3.0.\nUpgrade to cscope_15.3-1woody2\n');
}
if (deb_check(prefix: 'cscope', release: '3.1', reference: '15.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian 3.1.\nUpgrade to cscope_15.5-1\n');
}
if (deb_check(prefix: 'cscope', release: '3.0', reference: '15.3-1woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian woody.\nUpgrade to cscope_15.3-1woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
