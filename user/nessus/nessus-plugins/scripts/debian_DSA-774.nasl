# This script was automatically generated from the dsa-774
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Edward Shornock discovered a bug in the UIDL handling code of
fetchmail, a common POP3, APOP and IMAP mail fetching utility.  A
malicious POP3 server could exploit this problem and inject arbitrary
code that will be executed on the victim host.  If fetchmail is
running as root, this becomes a root exploit.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 6.2.5-16.
We recommend that you upgrade your fetchmail package.


Solution : http://www.debian.org/security/2005/dsa-774
Risk factor : High';

if (description) {
 script_id(19430);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "774");
 script_cve_id("CVE-2005-2335");
 script_bugtraq_id(14349);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA774] DSA-774-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-774-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fetchmail', release: '', reference: '6.2.5-16')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian .\nUpgrade to fetchmail_6.2.5-16\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 3.1.\nUpgrade to fetchmail_6.2.5-12sarge1\n');
}
if (deb_check(prefix: 'fetchmail-ssl', release: '3.1', reference: '6.2.5-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-ssl is vulnerable in Debian 3.1.\nUpgrade to fetchmail-ssl_6.2.5-12sarge1\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '3.1', reference: '6.2.5-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 3.1.\nUpgrade to fetchmailconf_6.2.5-12sarge1\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian sarge.\nUpgrade to fetchmail_6.2.5-12sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
