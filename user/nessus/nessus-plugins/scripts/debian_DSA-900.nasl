# This script was automatically generated from the dsa-900
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Due to restrictive dependency definition for fetchmail-ssl the updated fetchmailconf
package couldn\'t be installed on the old stable distribution (woody)
together with fetchmail-ssl.  Hence, this update loosens it, so that
the update can be pulled in.  For completeness we\'re including the
original advisory text:
Thomas Wolff discovered that the fetchmailconf program which is
provided as part of fetchmail, an SSL enabled POP3, APOP, IMAP mail
gatherer/forwarder, creates the new configuration in an insecure
fashion that can lead to leaking passwords for mail accounts to local
users.
This update also fixes a regression in the package for stable caused
by the last security update.
For the old stable distribution (woody) this problem has been fixed in
version 5.9.11-6.4 of fetchmail and in version 5.9.11-6.3 of
fetchmail-ssl.
For the stable distribution (sarge) this problem has been fixed in
version 6.2.5-12sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 6.2.5.4-1.
We recommend that you upgrade your fetchmail package.


Solution : http://www.debian.org/security/2005/dsa-900
Risk factor : High';

if (description) {
 script_id(22766);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "900");
 script_cve_id("CVE-2005-3088");
 script_bugtraq_id(15179);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA900] DSA-900-3 fetchmail");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-900-3 fetchmail");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'fetchmail', release: '', reference: '6.2.5.4-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian .\nUpgrade to fetchmail_6.2.5.4-1\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.0', reference: '5.9.11-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 3.0.\nUpgrade to fetchmail_5.9.11-6.4\n');
}
if (deb_check(prefix: 'fetchmail-common', release: '3.0', reference: '5.9.11-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-common is vulnerable in Debian 3.0.\nUpgrade to fetchmail-common_5.9.11-6.4\n');
}
if (deb_check(prefix: 'fetchmail-ssl', release: '3.0', reference: '5.9.11-6.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-ssl is vulnerable in Debian 3.0.\nUpgrade to fetchmail-ssl_5.9.11-6.3\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '3.0', reference: '5.9.11-6.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 3.0.\nUpgrade to fetchmailconf_5.9.11-6.4\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian 3.1.\nUpgrade to fetchmail_6.2.5-12sarge3\n');
}
if (deb_check(prefix: 'fetchmail-ssl', release: '3.1', reference: '6.2.5-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail-ssl is vulnerable in Debian 3.1.\nUpgrade to fetchmail-ssl_6.2.5-12sarge3\n');
}
if (deb_check(prefix: 'fetchmailconf', release: '3.1', reference: '6.2.5-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmailconf is vulnerable in Debian 3.1.\nUpgrade to fetchmailconf_6.2.5-12sarge3\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.1', reference: '6.2.5-12sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian sarge.\nUpgrade to fetchmail_6.2.5-12sarge3\n');
}
if (deb_check(prefix: 'fetchmail', release: '3.0', reference: '5.9.11-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package fetchmail is vulnerable in Debian woody.\nUpgrade to fetchmail_5.9.11-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
