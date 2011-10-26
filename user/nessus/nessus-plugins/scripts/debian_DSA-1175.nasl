# This script was automatically generated from the dsa-1175
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A flaw has been found in isakmpd, OpenBSD\'s implementation of the
Internet Key Exchange protocol, that caused Security Associations to be
created with a replay window of 0 when isakmpd was acting as the
responder during SA negotiation.  This could allow an attacker to
re-inject sniffed IPsec packets, which would not be checked against the
replay counter.
For the stable distribution (sarge) this problem has been fixed in
version 20041012-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 20041012-4.
We recommend that you upgrade your isakmpd package.


Solution : http://www.debian.org/security/2006/dsa-1175
Risk factor : High';

if (description) {
 script_id(22717);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1175");
 script_cve_id("CVE-2006-4436");
 script_bugtraq_id(19712);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1175] DSA-1175-1 isakmpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1175-1 isakmpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'isakmpd', release: '', reference: '20041012-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package isakmpd is vulnerable in Debian .\nUpgrade to isakmpd_20041012-4\n');
}
if (deb_check(prefix: 'isakmpd', release: '3.1', reference: '20041012-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package isakmpd is vulnerable in Debian 3.1.\nUpgrade to isakmpd_20041012-1sarge1\n');
}
if (deb_check(prefix: 'isakmpd', release: '3.1', reference: '20041012-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package isakmpd is vulnerable in Debian sarge.\nUpgrade to isakmpd_20041012-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
