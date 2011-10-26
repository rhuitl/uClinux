# This script was automatically generated from the dsa-861
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous41md" discovered a buffer overflow in uw-imap, the University
of Washington\'s IMAP Server that allows attackers to execute arbitrary
code.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2002edebian1-11sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2002edebian1-11sarge1.
We recommend that you upgrade your uw-imap packages.


Solution : http://www.debian.org/security/2005/dsa-861
Risk factor : High';

if (description) {
 script_id(19969);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "861");
 script_cve_id("CVE-2005-2933");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA861] DSA-861-1 uw-imap");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-861-1 uw-imap");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'uw-imap', release: '', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uw-imap is vulnerable in Debian .\nUpgrade to uw-imap_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'ipopd', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipopd is vulnerable in Debian 3.1.\nUpgrade to ipopd_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'ipopd-ssl', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipopd-ssl is vulnerable in Debian 3.1.\nUpgrade to ipopd-ssl_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'libc-client-dev', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc-client-dev is vulnerable in Debian 3.1.\nUpgrade to libc-client-dev_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'libc-client2002edebian', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libc-client2002edebian is vulnerable in Debian 3.1.\nUpgrade to libc-client2002edebian_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'mlock', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mlock is vulnerable in Debian 3.1.\nUpgrade to mlock_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'uw-imapd', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uw-imapd is vulnerable in Debian 3.1.\nUpgrade to uw-imapd_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'uw-imapd-ssl', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uw-imapd-ssl is vulnerable in Debian 3.1.\nUpgrade to uw-imapd-ssl_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'uw-mailutils', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uw-mailutils is vulnerable in Debian 3.1.\nUpgrade to uw-mailutils_2002edebian1-11sarge1\n');
}
if (deb_check(prefix: 'uw-imap', release: '3.1', reference: '2002edebian1-11sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package uw-imap is vulnerable in Debian sarge.\nUpgrade to uw-imap_2002edebian1-11sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
