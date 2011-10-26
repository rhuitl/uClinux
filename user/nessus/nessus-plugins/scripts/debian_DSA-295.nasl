# This script was automatically generated from the dsa-295
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Timo Sirainen discovered a vulnerability in pptpd, a Point to Point
Tunneling Server, which implements PPTP-over-IPSEC and is commonly
used to create Virtual Private Networks (VPN).  By specifying a small
packet length an attacker is able to overflow a buffer and execute
code under the user id that runs pptpd, probably root.  An exploit for
this problem is already circulating.
For the stable distribution (woody) this problem has been fixed in
version 1.1.2-1.4.
For the old stable distribution (potato) this problem has been
fixed in version 1.0.0-4.2.
For the unstable distribution (sid) this problem has been fixed in
version 1.1.4-0.b3.2.
We recommend that you upgrade your pptpd package immediately.


Solution : http://www.debian.org/security/2003/dsa-295
Risk factor : High';

if (description) {
 script_id(15132);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "295");
 script_cve_id("CVE-2003-0213");
 script_bugtraq_id(7316);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA295] DSA-295-1 pptpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-295-1 pptpd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'pptpd', release: '2.2', reference: '1.0.0-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pptpd is vulnerable in Debian 2.2.\nUpgrade to pptpd_1.0.0-4.2\n');
}
if (deb_check(prefix: 'pptpd', release: '3.0', reference: '1.1.2-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pptpd is vulnerable in Debian 3.0.\nUpgrade to pptpd_1.1.2-1.4\n');
}
if (deb_check(prefix: 'pptpd', release: '3.1', reference: '1.1.4-0.b3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pptpd is vulnerable in Debian 3.1.\nUpgrade to pptpd_1.1.4-0.b3.2\n');
}
if (deb_check(prefix: 'pptpd', release: '2.2', reference: '1.0.0-4.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pptpd is vulnerable in Debian potato.\nUpgrade to pptpd_1.0.0-4.2\n');
}
if (deb_check(prefix: 'pptpd', release: '3.0', reference: '1.1.2-1.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package pptpd is vulnerable in Debian woody.\nUpgrade to pptpd_1.1.2-1.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
