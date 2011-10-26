# This script was automatically generated from the dsa-281
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Knud Erik Højgaard discovered a vulnerability in moxftp (and xftp
respectively), an Athena X interface to FTP.  Insufficient bounds
checking could lead to execution of arbitrary code, provided by a
malicious FTP server.   Erik Tews fixed this.
For the stable distribution (woody) this problem has been fixed in
version 2.2-18.1.
For the old stable distribution (potato) this problem has been fixed
in version 2.2-13.1.
For the unstable distribution (sid) this problem has been fixed
in version 2.2-18.20.
We recommend that you upgrade your xftp package.


Solution : http://www.debian.org/security/2003/dsa-281
Risk factor : High';

if (description) {
 script_id(15118);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "281");
 script_cve_id("CVE-2003-0203");
 script_bugtraq_id(6921);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA281] DSA-281-1 moxftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-281-1 moxftp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'xftp', release: '2.2', reference: '2.2-13.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xftp is vulnerable in Debian 2.2.\nUpgrade to xftp_2.2-13.1\n');
}
if (deb_check(prefix: 'xftp', release: '3.0', reference: '2.2-18.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package xftp is vulnerable in Debian 3.0.\nUpgrade to xftp_2.2-18.1\n');
}
if (deb_check(prefix: 'moxftp', release: '3.1', reference: '2.2-18.20')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package moxftp is vulnerable in Debian 3.1.\nUpgrade to moxftp_2.2-18.20\n');
}
if (deb_check(prefix: 'moxftp', release: '2.2', reference: '2.2-13.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package moxftp is vulnerable in Debian potato.\nUpgrade to moxftp_2.2-13.1\n');
}
if (deb_check(prefix: 'moxftp', release: '3.0', reference: '2.2-18.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package moxftp is vulnerable in Debian woody.\nUpgrade to moxftp_2.2-18.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
