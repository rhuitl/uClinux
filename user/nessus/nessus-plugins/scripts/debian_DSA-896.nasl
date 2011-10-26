# This script was automatically generated from the dsa-896
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A buffer overflow has been discovered in ftpd-ssl, a simple BSD FTP
server with SSL encryption support, that could lead to the execution
of arbitrary code.
The old stable distribution (woody) does not contain linux-ftpd-ssl
packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.17.18+0.3-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.17.18+0.3-5.
We recommend that you upgrade your ftpd-ssl package.


Solution : http://www.debian.org/security/2005/dsa-896
Risk factor : High';

if (description) {
 script_id(22762);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "896");
 script_cve_id("CVE-2005-3524");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA896] DSA-896-1 linux-ftpd-ssl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-896-1 linux-ftpd-ssl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'linux-ftpd-ssl', release: '', reference: '0.17.18+0.3-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package linux-ftpd-ssl is vulnerable in Debian .\nUpgrade to linux-ftpd-ssl_0.17.18+0.3-5\n');
}
if (deb_check(prefix: 'ftpd-ssl', release: '3.1', reference: '0.17.18+0.3-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ftpd-ssl is vulnerable in Debian 3.1.\nUpgrade to ftpd-ssl_0.17.18+0.3-3sarge1\n');
}
if (deb_check(prefix: 'linux-ftpd-ssl', release: '3.1', reference: '0.17.18+0.3-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package linux-ftpd-ssl is vulnerable in Debian sarge.\nUpgrade to linux-ftpd-ssl_0.17.18+0.3-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
