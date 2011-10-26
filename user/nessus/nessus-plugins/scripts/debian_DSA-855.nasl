# This script was automatically generated from the dsa-855
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered a
format string vulnerability in weex, a non-interactive FTP client for
updating web pages, that could be exploited to execute arbitrary code
on the clients machine.
For the old stable distribution (woody) this problem has been fixed in
version 2.6.1-4woody2.
For the stable distribution (sarge) this problem has been fixed in
version 2.6.1-6sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.6.1-6sarge1.
We recommend that you upgrade your weex package.


Solution : http://www.debian.org/security/2005/dsa-855
Risk factor : High';

if (description) {
 script_id(19963);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "855");
 script_cve_id("CVE-2005-3150");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA855] DSA-855-1 weex");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-855-1 weex");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'weex', release: '', reference: '2.6.1-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package weex is vulnerable in Debian .\nUpgrade to weex_2.6.1-6sarge1\n');
}
if (deb_check(prefix: 'weex', release: '3.0', reference: '2.6.1-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package weex is vulnerable in Debian 3.0.\nUpgrade to weex_2.6.1-4woody2\n');
}
if (deb_check(prefix: 'weex', release: '3.1', reference: '2.6.1-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package weex is vulnerable in Debian 3.1.\nUpgrade to weex_2.6.1-6sarge1\n');
}
if (deb_check(prefix: 'weex', release: '3.1', reference: '2.6.1-6sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package weex is vulnerable in Debian sarge.\nUpgrade to weex_2.6.1-6sarge1\n');
}
if (deb_check(prefix: 'weex', release: '3.0', reference: '2.6.1-4woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package weex is vulnerable in Debian woody.\nUpgrade to weex_2.6.1-4woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
