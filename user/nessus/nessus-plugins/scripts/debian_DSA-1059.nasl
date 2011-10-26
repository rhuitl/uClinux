# This script was automatically generated from the dsa-1059
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Konstantin Gavrilenko discovered several vulnerabilities in quagga,
the BGP/OSPF/RIP routing daemon.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Remote attackers may obtain sensitive information via RIPv1
    REQUEST packets even if the quagga has been configured to use MD5
    authentication.
    Remote attackers could inject arbitrary routes using the RIPv1
    RESPONSE packet even if the quagga has been configured to use MD5
    authentication.
    Fredrik Widell discovered that local users can cause a denial
    of service in a certain sh ip bgp command entered in the telnet
    interface.
The old stable distribution (woody) does not contain quagga packages.
For the stable distribution (sarge) these problems have been fixed in
version 0.98.3-7.2.
For the unstable distribution (sid) these problems have been fixed in
version 0.99.4-1.
We recommend that you upgrade your quagga package.


Solution : http://www.debian.org/security/2006/dsa-1059
Risk factor : High';

if (description) {
 script_id(22601);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1059");
 script_cve_id("CVE-2006-2223", "CVE-2006-2224", "CVE-2006-2276");
 script_bugtraq_id(17808);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1059] DSA-1059-1 quagga");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1059-1 quagga");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'quagga', release: '', reference: '0.99.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package quagga is vulnerable in Debian .\nUpgrade to quagga_0.99.4-1\n');
}
if (deb_check(prefix: 'quagga', release: '3.1', reference: '0.98.3-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package quagga is vulnerable in Debian 3.1.\nUpgrade to quagga_0.98.3-7.2\n');
}
if (deb_check(prefix: 'quagga-doc', release: '3.1', reference: '0.98.3-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package quagga-doc is vulnerable in Debian 3.1.\nUpgrade to quagga-doc_0.98.3-7.2\n');
}
if (deb_check(prefix: 'quagga', release: '3.1', reference: '0.98.3-7.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package quagga is vulnerable in Debian sarge.\nUpgrade to quagga_0.98.3-7.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
