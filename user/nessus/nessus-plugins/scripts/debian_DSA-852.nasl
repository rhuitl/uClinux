# This script was automatically generated from the dsa-852
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Steve Kemp discovered two format string vulnerabilities in
up-imapproxy, an IMAP protocol proxy, which may lead remote attackers
to the execution of arbitrary code.
The old stable distribution (woody) is not affected by these problems.
For the stable distribution (sarge) these problems have been fixed in
version 1.2.3-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 1.2.4-2.
We recommend that you upgrade your imapproxy package.


Solution : http://www.debian.org/security/2005/dsa-852
Risk factor : High';

if (description) {
 script_id(19960);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "852");
 script_cve_id("CVE-2005-2661");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA852] DSA-852-1 up-imapproxy");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-852-1 up-imapproxy");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'up-imapproxy', release: '', reference: '1.2.4-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package up-imapproxy is vulnerable in Debian .\nUpgrade to up-imapproxy_1.2.4-2\n');
}
if (deb_check(prefix: 'imapproxy', release: '3.1', reference: '1.2.3-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package imapproxy is vulnerable in Debian 3.1.\nUpgrade to imapproxy_1.2.3-1sarge1\n');
}
if (deb_check(prefix: 'up-imapproxy', release: '3.1', reference: '1.2.3-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package up-imapproxy is vulnerable in Debian sarge.\nUpgrade to up-imapproxy_1.2.3-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
