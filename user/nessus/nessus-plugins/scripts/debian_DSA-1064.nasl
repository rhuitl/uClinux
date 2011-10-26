# This script was automatically generated from the dsa-1064
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Jason Duell discovered that cscope, a source code browsing tool, does not
verify the length of file names sourced in include statements, which may
potentially lead to the execution of arbitrary code through specially
crafted source code files.
For the old stable distribution (woody) this problem has been fixed in
version 15.3-1woody3.
For the stable distribution (sarge) this problem has been fixed in
version 15.5-1.1sarge1.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your cscope package.


Solution : http://www.debian.org/security/2006/dsa-1064
Risk factor : High';

if (description) {
 script_id(22606);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1064");
 script_cve_id("CVE-2004-2541");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1064] DSA-1064-1 cscope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1064-1 cscope");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cscope', release: '3.0', reference: '15.3-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian 3.0.\nUpgrade to cscope_15.3-1woody3\n');
}
if (deb_check(prefix: 'cscope', release: '3.1', reference: '15.5-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian 3.1.\nUpgrade to cscope_15.5-1.1sarge1\n');
}
if (deb_check(prefix: 'cscope', release: '3.1', reference: '15.5-1.1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian sarge.\nUpgrade to cscope_15.5-1.1sarge1\n');
}
if (deb_check(prefix: 'cscope', release: '3.0', reference: '15.3-1woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian woody.\nUpgrade to cscope_15.3-1woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
