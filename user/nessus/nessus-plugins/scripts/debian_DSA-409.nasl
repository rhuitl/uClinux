# This script was automatically generated from the dsa-409
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability was discovered in BIND, a domain name server, whereby
a malicious name server could return authoritative negative responses
with a large TTL (time-to-live) value, thereby rendering a domain name
unreachable.  A successful attack would require that a vulnerable BIND
instance submit a query to a malicious nameserver. 
The bind9 package is not affected by this vulnerability.
For the current stable distribution (woody) this problem has been
fixed in version 1:8.3.3-2.0woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1:8.4.3-1.
We recommend that you update your bind package.


Solution : http://www.debian.org/security/2004/dsa-409
Risk factor : High';

if (description) {
 script_id(15246);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "409");
 script_cve_id("CVE-2003-0914");
 script_bugtraq_id(9114);
 script_xref(name: "CERT", value: "734644");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA409] DSA-409-1 bind");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-409-1 bind");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bind', release: '3.0', reference: '8.3.3-2.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind is vulnerable in Debian 3.0.\nUpgrade to bind_8.3.3-2.0woody2\n');
}
if (deb_check(prefix: 'bind-dev', release: '3.0', reference: '8.3.3-2.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind-dev is vulnerable in Debian 3.0.\nUpgrade to bind-dev_8.3.3-2.0woody2\n');
}
if (deb_check(prefix: 'bind-doc', release: '3.0', reference: '8.3.3-2.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind-doc is vulnerable in Debian 3.0.\nUpgrade to bind-doc_8.3.3-2.0woody2\n');
}
if (deb_check(prefix: 'bind', release: '3.1', reference: '8.4.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind is vulnerable in Debian 3.1.\nUpgrade to bind_8.4.3-1\n');
}
if (deb_check(prefix: 'bind', release: '3.0', reference: '8.3.3-2.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bind is vulnerable in Debian woody.\nUpgrade to bind_8.3.3-2.0woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
