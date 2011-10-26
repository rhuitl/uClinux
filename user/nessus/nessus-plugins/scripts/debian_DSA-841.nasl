# This script was automatically generated from the dsa-841
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A format string vulnerability has been discovered in GNU mailutils
which contains utilities for handling mail that allows a remote
attacker to execute arbitrary code on the IMAP server.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.6.1-4sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.6.90-3.
We recommend that you upgrade your mailutils package.


Solution : http://www.debian.org/security/2005/dsa-841
Risk factor : High';

if (description) {
 script_id(19845);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "841");
 script_cve_id("CVE-2005-2878");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA841] DSA-841-1 mailutils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-841-1 mailutils");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailutils', release: '', reference: '0.6.90-3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils is vulnerable in Debian .\nUpgrade to mailutils_0.6.90-3\n');
}
if (deb_check(prefix: 'libmailutils0', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmailutils0 is vulnerable in Debian 3.1.\nUpgrade to libmailutils0_0.6.1-4sarge1\n');
}
if (deb_check(prefix: 'libmailutils0-dev', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libmailutils0-dev is vulnerable in Debian 3.1.\nUpgrade to libmailutils0-dev_0.6.1-4sarge1\n');
}
if (deb_check(prefix: 'mailutils', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils is vulnerable in Debian 3.1.\nUpgrade to mailutils_0.6.1-4sarge1\n');
}
if (deb_check(prefix: 'mailutils-comsatd', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils-comsatd is vulnerable in Debian 3.1.\nUpgrade to mailutils-comsatd_0.6.1-4sarge1\n');
}
if (deb_check(prefix: 'mailutils-doc', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils-doc is vulnerable in Debian 3.1.\nUpgrade to mailutils-doc_0.6.1-4sarge1\n');
}
if (deb_check(prefix: 'mailutils-imap4d', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils-imap4d is vulnerable in Debian 3.1.\nUpgrade to mailutils-imap4d_0.6.1-4sarge1\n');
}
if (deb_check(prefix: 'mailutils-mh', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils-mh is vulnerable in Debian 3.1.\nUpgrade to mailutils-mh_0.6.1-4sarge1\n');
}
if (deb_check(prefix: 'mailutils-pop3d', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils-pop3d is vulnerable in Debian 3.1.\nUpgrade to mailutils-pop3d_0.6.1-4sarge1\n');
}
if (deb_check(prefix: 'mailutils', release: '3.1', reference: '0.6.1-4sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailutils is vulnerable in Debian sarge.\nUpgrade to mailutils_0.6.1-4sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
