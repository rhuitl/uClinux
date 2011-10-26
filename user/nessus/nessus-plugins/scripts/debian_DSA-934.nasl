# This script was automatically generated from the dsa-934
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two vulnerabilities have been discovered in Pound, a reverse proxy and
load balancer for HTTP. The Common Vulnerabilities and Exposures project
identifies the following problems:
     Overly long HTTP Host: headers may trigger a buffer overflow in the
     add_port() function, which may lead to the execution of arbitrary
     code.
     HTTP requests with conflicting Content-Length and Transfer-Encoding
     headers could lead to HTTP Request Smuggling Attack, which can be
     exploited to bypass packet filters or poison web caches.
The old stable distribution (woody) does not contain pound packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.8.2-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 1.9.4-1.
We recommend that you upgrade your pound package.


Solution : http://www.debian.org/security/2006/dsa-934
Risk factor : High';

if (description) {
 script_id(22800);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "934");
 script_cve_id("CVE-2005-1391", "CVE-2005-3751");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA934] DSA-934-1 pound");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-934-1 pound");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pound', release: '', reference: '1.9.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pound is vulnerable in Debian .\nUpgrade to pound_1.9.4-1\n');
}
if (deb_check(prefix: 'pound', release: '3.1', reference: '1.8.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pound is vulnerable in Debian 3.1.\nUpgrade to pound_1.8.2-1sarge1\n');
}
if (deb_check(prefix: 'pound', release: '3.1', reference: '1.8.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pound is vulnerable in Debian sarge.\nUpgrade to pound_1.8.2-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
