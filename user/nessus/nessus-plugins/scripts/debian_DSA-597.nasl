# This script was automatically generated from the dsa-597
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Stefan Esser discovered several security related problems in the Cyrus
IMAP daemon.  Due to a bug in the command parser it is possible to
access memory beyond the allocated buffer in two places which could
lead to the execution of arbitrary code.
For the stable distribution (woody) these problems have been fixed in
version 1.5.19-9.2
For the unstable distribution (sid) these problems have been fixed in
version 2.1.17-1.
We recommend that you upgrade your cyrus-imapd package immediately.


Solution : http://www.debian.org/security/2004/dsa-597
Risk factor : High';

if (description) {
 script_id(15830);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "597");
 script_cve_id("CVE-2004-1012", "CVE-2004-1013");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA597] DSA-597-1 cyrus-imapd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-597-1 cyrus-imapd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cyrus-admin', release: '3.0', reference: '1.5.19-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-admin is vulnerable in Debian 3.0.\nUpgrade to cyrus-admin_1.5.19-9.2\n');
}
if (deb_check(prefix: 'cyrus-common', release: '3.0', reference: '1.5.19-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-common is vulnerable in Debian 3.0.\nUpgrade to cyrus-common_1.5.19-9.2\n');
}
if (deb_check(prefix: 'cyrus-dev', release: '3.0', reference: '1.5.19-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-dev is vulnerable in Debian 3.0.\nUpgrade to cyrus-dev_1.5.19-9.2\n');
}
if (deb_check(prefix: 'cyrus-imapd', release: '3.0', reference: '1.5.19-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-imapd is vulnerable in Debian 3.0.\nUpgrade to cyrus-imapd_1.5.19-9.2\n');
}
if (deb_check(prefix: 'cyrus-nntp', release: '3.0', reference: '1.5.19-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-nntp is vulnerable in Debian 3.0.\nUpgrade to cyrus-nntp_1.5.19-9.2\n');
}
if (deb_check(prefix: 'cyrus-pop3d', release: '3.0', reference: '1.5.19-9.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-pop3d is vulnerable in Debian 3.0.\nUpgrade to cyrus-pop3d_1.5.19-9.2\n');
}
if (deb_check(prefix: 'cyrus-imapd', release: '3.1', reference: '2.1.17-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-imapd is vulnerable in Debian 3.1.\nUpgrade to cyrus-imapd_2.1.17-1\n');
}
if (deb_check(prefix: 'cyrus-imapd', release: '3.0', reference: '1.5.19-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cyrus-imapd is vulnerable in Debian woody.\nUpgrade to cyrus-imapd_1.5.19-9\n');
}
if (w) { security_hole(port: 0, data: desc); }
