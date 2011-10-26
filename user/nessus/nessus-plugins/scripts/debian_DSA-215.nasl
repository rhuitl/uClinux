# This script was automatically generated from the dsa-215
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Timo Sirainen discovered a buffer overflow in the Cyrus IMAP server,
which could be exploited by a remote attacker prior to logging in.  A
malicious user could craft a request to run commands on the server under
the UID and GID of the cyrus server.
For the current stable distribution (woody) this problem has been
fixed in version 1.5.19-9.1.
For the old stable distribution (potato) this problem has been fixed
in version 1.5.19-2.2.
For the unstable distribution (sid) this problem has been
fixed in version 1.5.19-9.10.  Current cyrus21-imapd packages are not
vulnerable.
We recommend that you upgrade your cyrus-imapd package.


Solution : http://www.debian.org/security/2002/dsa-215
Risk factor : High';

if (description) {
 script_id(15052);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "215");
 script_cve_id("CVE-2002-1580");
 script_bugtraq_id(6298);
 script_xref(name: "CERT", value: "740169");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA215] DSA-215-1 cyrus-imapd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-215-1 cyrus-imapd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cyrus-admin', release: '2.2', reference: '1.5.19-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-admin is vulnerable in Debian 2.2.\nUpgrade to cyrus-admin_1.5.19-2.2\n');
}
if (deb_check(prefix: 'cyrus-common', release: '2.2', reference: '1.5.19-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-common is vulnerable in Debian 2.2.\nUpgrade to cyrus-common_1.5.19-2.2\n');
}
if (deb_check(prefix: 'cyrus-dev', release: '2.2', reference: '1.5.19-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-dev is vulnerable in Debian 2.2.\nUpgrade to cyrus-dev_1.5.19-2.2\n');
}
if (deb_check(prefix: 'cyrus-imapd', release: '2.2', reference: '1.5.19-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-imapd is vulnerable in Debian 2.2.\nUpgrade to cyrus-imapd_1.5.19-2.2\n');
}
if (deb_check(prefix: 'cyrus-nntp', release: '2.2', reference: '1.5.19-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-nntp is vulnerable in Debian 2.2.\nUpgrade to cyrus-nntp_1.5.19-2.2\n');
}
if (deb_check(prefix: 'cyrus-pop3d', release: '2.2', reference: '1.5.19-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-pop3d is vulnerable in Debian 2.2.\nUpgrade to cyrus-pop3d_1.5.19-2.2\n');
}
if (deb_check(prefix: 'cyrus-admin', release: '3.0', reference: '1.5.19-9.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-admin is vulnerable in Debian 3.0.\nUpgrade to cyrus-admin_1.5.19-9.1\n');
}
if (deb_check(prefix: 'cyrus-common', release: '3.0', reference: '1.5.19-9.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-common is vulnerable in Debian 3.0.\nUpgrade to cyrus-common_1.5.19-9.1\n');
}
if (deb_check(prefix: 'cyrus-dev', release: '3.0', reference: '1.5.19-9.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-dev is vulnerable in Debian 3.0.\nUpgrade to cyrus-dev_1.5.19-9.1\n');
}
if (deb_check(prefix: 'cyrus-imapd', release: '3.0', reference: '1.5.19-9.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-imapd is vulnerable in Debian 3.0.\nUpgrade to cyrus-imapd_1.5.19-9.1\n');
}
if (deb_check(prefix: 'cyrus-nntp', release: '3.0', reference: '1.5.19-9.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-nntp is vulnerable in Debian 3.0.\nUpgrade to cyrus-nntp_1.5.19-9.1\n');
}
if (deb_check(prefix: 'cyrus-pop3d', release: '3.0', reference: '1.5.19-9.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-pop3d is vulnerable in Debian 3.0.\nUpgrade to cyrus-pop3d_1.5.19-9.1\n');
}
if (deb_check(prefix: 'cyrus-imapd', release: '3.1', reference: '1.5.19-9.10')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-imapd is vulnerable in Debian 3.1.\nUpgrade to cyrus-imapd_1.5.19-9.10\n');
}
if (deb_check(prefix: 'cyrus-imapd', release: '2.2', reference: '1.5.19-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-imapd is vulnerable in Debian potato.\nUpgrade to cyrus-imapd_1.5.19-2.2\n');
}
if (deb_check(prefix: 'cyrus-imapd', release: '3.0', reference: '1.5.19-9.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-imapd is vulnerable in Debian woody.\nUpgrade to cyrus-imapd_1.5.19-9.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
