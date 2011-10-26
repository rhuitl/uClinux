# This script was automatically generated from the dsa-251
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Hironori Sakamoto, one of the w3m developers, found two security
vulnerabilities in w3m and associated programs.  The w3m browser does
not properly escape HTML tags in frame contents and img alt
attributes.  A malicious HTML frame or img alt attribute may deceive a
user to send their local cookies which are used for configuration.  The
information is not leaked automatically, though.
For the stable distribution (woody) these problems have been fixed in
version 0.3-2.4.
The old stable distribution (potato) is not affected by these
problems.
For the unstable distribution (sid) these problems have been fixed in
version 0.3.2.2-1 and later.
We recommend that you upgrade your w3m and w3m-ssl packages.


Solution : http://www.debian.org/security/2003/dsa-251
Risk factor : High';

if (description) {
 script_id(15088);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "251");
 script_cve_id("CVE-2002-1335", "CVE-2002-1348");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA251] DSA-251-1 w3m");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-251-1 w3m");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'w3m', release: '3.0', reference: '0.3-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package w3m is vulnerable in Debian 3.0.\nUpgrade to w3m_0.3-2.4\n');
}
if (deb_check(prefix: 'w3m-img', release: '3.0', reference: '0.3-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package w3m-img is vulnerable in Debian 3.0.\nUpgrade to w3m-img_0.3-2.4\n');
}
if (deb_check(prefix: 'w3m-ssl', release: '3.0', reference: '0.3-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package w3m-ssl is vulnerable in Debian 3.0.\nUpgrade to w3m-ssl_0.3-2.4\n');
}
if (deb_check(prefix: 'w3m,', release: '3.1', reference: '0.3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package w3m, is vulnerable in Debian 3.1.\nUpgrade to w3m,_0.3.2\n');
}
if (deb_check(prefix: 'w3m,', release: '3.0', reference: '0.3-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package w3m, is vulnerable in Debian woody.\nUpgrade to w3m,_0.3-2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
