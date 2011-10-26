# This script was automatically generated from the dsa-474
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in squid, an Internet object cache,
whereby access control lists based on URLs could be bypassed
(CVE-2004-0189).  Two other bugs were also fixed with patches
squid-2.4.STABLE7-url_escape.patch (a buffer overrun which does not
appear to be exploitable) and squid-2.4.STABLE7-url_port.patch (a
potential denial of service).
For the stable distribution (woody) these problems have been fixed in
version 2.4.6-2woody2.
For the unstable distribution (sid) these problems have been fixed in
version 2.5.5-1.
We recommend that you update your squid package.


Solution : http://www.debian.org/security/2004/dsa-474
Risk factor : High';

if (description) {
 script_id(15311);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "474");
 script_cve_id("CVE-2004-0189");
 script_bugtraq_id(9778);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA474] DSA-474-1 squid");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-474-1 squid");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.0.\nUpgrade to squid_2.4.6-2woody2\n');
}
if (deb_check(prefix: 'squid-cgi', release: '3.0', reference: '2.4.6-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid-cgi is vulnerable in Debian 3.0.\nUpgrade to squid-cgi_2.4.6-2woody2\n');
}
if (deb_check(prefix: 'squidclient', release: '3.0', reference: '2.4.6-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squidclient is vulnerable in Debian 3.0.\nUpgrade to squidclient_2.4.6-2woody2\n');
}
if (deb_check(prefix: 'squid', release: '3.1', reference: '2.5.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian 3.1.\nUpgrade to squid_2.5.5-1\n');
}
if (deb_check(prefix: 'squid', release: '3.0', reference: '2.4.6-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package squid is vulnerable in Debian woody.\nUpgrade to squid_2.4.6-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
