# This script was automatically generated from the dsa-1186
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Will Drewry of the Google Security Team discovered several buffer overflows
in cscope, a source browsing tool, which might lead to the execution of
arbitrary code.
For the stable distribution (sarge) this problem has been fixed in
version 15.5-1.1sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 15.5+cvs20060902-1.
We recommend that you upgrade your cscope package.


Solution : http://www.debian.org/security/2006/dsa-1186
Risk factor : High';

if (description) {
 script_id(22728);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1186");
 script_cve_id("CVE-2006-4262");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1186] DSA-1186-1 cscope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1186-1 cscope");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cscope', release: '', reference: '15.5+cvs20060902-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian .\nUpgrade to cscope_15.5+cvs20060902-1\n');
}
if (deb_check(prefix: 'cscope', release: '3.1', reference: '15.5-1.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian 3.1.\nUpgrade to cscope_15.5-1.1sarge2\n');
}
if (deb_check(prefix: 'cscope', release: '3.1', reference: '15.5-1.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cscope is vulnerable in Debian sarge.\nUpgrade to cscope_15.5-1.1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
