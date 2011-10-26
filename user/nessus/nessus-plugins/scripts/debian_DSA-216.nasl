# This script was automatically generated from the dsa-216
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser of e-matters discovered a buffer overflow in fetchmail,
an SSL enabled POP3, APOP and IMAP mail gatherer/forwarder.  When
fetchmail retrieves a mail all headers that contain addresses are
searched for local addresses.  If a hostname is missing, fetchmail
appends it but doesn\'t reserve enough space for it.  This heap
overflow can be used by remote attackers to crash it or to execute
arbitrary code with the privileges of the user running fetchmail.
For the current stable distribution (woody) this problem has been
fixed in version 5.9.11-6.2 of fetchmail and fetchmail-ssl.
For the old stable distribution (potato) this problem has been fixed
in version 5.3.3-4.3.
For the unstable distribution (sid) this problem has been
fixed in version 6.2.0-1 of fetchmail and fetchmail-ssl.
We recommend that you upgrade your fetchmail packages.


Solution : http://www.debian.org/security/2002/dsa-216
Risk factor : High';

if (description) {
 script_id(15053);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "216");
 script_cve_id("CVE-2002-1365");
 script_bugtraq_id(6390);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA216] DSA-216-1 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-216-1 fetchmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-4.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 2.2.\nUpgrade to fetchmail_5.3.3-4.3\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '2.2', reference: '5.3.3-4.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 2.2.\nUpgrade to fetchmailconf_5.3.3-4.3\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.0', reference: '5.9.11-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 3.0.\nUpgrade to fetchmail_5.9.11-6.2\n');
}
if (deb_check(prefix: 'fetchmail-common', release: '3.0', reference: '5.9.11-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-common is vulnerable in Debian 3.0.\nUpgrade to fetchmail-common_5.9.11-6.2\n');
}
if (deb_check(prefix: 'fetchmail-ssl', release: '3.0', reference: '5.9.11-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-ssl is vulnerable in Debian 3.0.\nUpgrade to fetchmail-ssl_5.9.11-6.2\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '3.0', reference: '5.9.11-6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 3.0.\nUpgrade to fetchmailconf_5.9.11-6.2\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 3.1.\nUpgrade to fetchmail_6.2\n');
}
if (deb_check(prefix: 'fetchmail', release: '2.2', reference: '5.3.3-4.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian potato.\nUpgrade to fetchmail_5.3.3-4.3\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.0', reference: '5.9.11-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian woody.\nUpgrade to fetchmail_5.9.11-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
