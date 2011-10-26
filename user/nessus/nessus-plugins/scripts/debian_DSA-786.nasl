# This script was automatically generated from the dsa-786
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Ulf Härnhammar from the Debian Security Audit Project discovered a
format string vulnerability in simpleproxy, a simple TCP proxy, that
can be exploited via replies from remote HTTP proxies.
The old stable distribution (woody) is not affected.
For the stable distribution (sarge) this problem has been fixed in
version 3.2-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 3.2-4.
We recommend that you upgrade your simpleproxy package.


Solution : http://www.debian.org/security/2005/dsa-786
Risk factor : High';

if (description) {
 script_id(19529);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "786");
 script_cve_id("CVE-2005-1857");
 script_xref(name: "CERT", value: "139421");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA786] DSA-786-1 simpleproxy");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-786-1 simpleproxy");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'simpleproxy', release: '', reference: '3.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package simpleproxy is vulnerable in Debian .\nUpgrade to simpleproxy_3.2-4\n');
}
if (deb_check(prefix: 'simpleproxy', release: '3.1', reference: '3.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package simpleproxy is vulnerable in Debian 3.1.\nUpgrade to simpleproxy_3.2-3sarge1\n');
}
if (deb_check(prefix: 'simpleproxy', release: '3.1', reference: '3.2-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package simpleproxy is vulnerable in Debian sarge.\nUpgrade to simpleproxy_3.2-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
