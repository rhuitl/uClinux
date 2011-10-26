# This script was automatically generated from the dsa-1080
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in the IMAP component of Dovecot, a
secure mail server that supports mbox and maildir mailboxes, which can
lead to information disclosure via directory traversal by
authenticated users.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 0.99.14-1sarge0.
For the unstable distribution (sid) this problem has been fixed in
version 1.0beta8-1.
We recommend that you upgrade your dovecot-imapd package.


Solution : http://www.debian.org/security/2006/dsa-1080
Risk factor : High';

if (description) {
 script_id(22622);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1080");
 script_cve_id("CVE-2006-2414");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1080] DSA-1080-1 dovecot");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1080-1 dovecot");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dovecot', release: '', reference: '1.0beta8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dovecot is vulnerable in Debian .\nUpgrade to dovecot_1.0beta8-1\n');
}
if (deb_check(prefix: 'dovecot', release: '3.1', reference: '0.99.14-1sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dovecot is vulnerable in Debian 3.1.\nUpgrade to dovecot_0.99.14-1sarge0\n');
}
if (deb_check(prefix: 'dovecot-common', release: '3.1', reference: '0.99.14-1sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dovecot-common is vulnerable in Debian 3.1.\nUpgrade to dovecot-common_0.99.14-1sarge0\n');
}
if (deb_check(prefix: 'dovecot-imapd', release: '3.1', reference: '0.99.14-1sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dovecot-imapd is vulnerable in Debian 3.1.\nUpgrade to dovecot-imapd_0.99.14-1sarge0\n');
}
if (deb_check(prefix: 'dovecot-pop3d', release: '3.1', reference: '0.99.14-1sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dovecot-pop3d is vulnerable in Debian 3.1.\nUpgrade to dovecot-pop3d_0.99.14-1sarge0\n');
}
if (deb_check(prefix: 'dovecot', release: '3.1', reference: '0.99.14-1sarge0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dovecot is vulnerable in Debian sarge.\nUpgrade to dovecot_0.99.14-1sarge0\n');
}
if (w) { security_hole(port: 0, data: desc); }
