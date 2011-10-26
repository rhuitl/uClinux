# This script was automatically generated from the dsa-939
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Daniel Drake discovered a problem in fetchmail, an SSL enabled POP3,
APOP, IMAP mail gatherer/forwarder, that can cause a crash when the
program is running in multidrop mode and receives messages without
headers.
The old stable distribution (woody) does not seem to be affected by
this problem.
For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge4.
For the unstable distribution (sid) this problem has been fixed in
version 6.3.1-1.
We recommend that you upgrade your fetchmail package.


Solution : http://www.debian.org/security/2006/dsa-939
Risk factor : High';

if (description) {
 script_id(22805);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "939");
 script_cve_id("CVE-2005-4348");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA939] DSA-939-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-939-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fetchmail', release: '', reference: '6.3.1-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian .\nUpgrade to fetchmail_6.3.1-1\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 3.1.\nUpgrade to fetchmail_6.2.5-12sarge4\n');
}
if (deb_check(prefix: 'fetchmail-ssl', release: '3.1', reference: '6.2.5-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-ssl is vulnerable in Debian 3.1.\nUpgrade to fetchmail-ssl_6.2.5-12sarge4\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '3.1', reference: '6.2.5-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 3.1.\nUpgrade to fetchmailconf_6.2.5-12sarge4\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian sarge.\nUpgrade to fetchmail_6.2.5-12sarge4\n');
}
if (w) { security_hole(port: 0, data: desc); }
