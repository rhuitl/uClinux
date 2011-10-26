# This script was automatically generated from the dsa-1045
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Hendrik Weimer discovered that OpenVPN, the Virtual Private Network
daemon, allows to push environment variables to a client allowing a
malicious VPN server to take over connected clients.
The old stable distribution (woody) does not contain openvpn packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.0-1sarge3.
For the unstable distribution (sid) this problem has been fixed in
version 2.0.6-1.
We recommend that you upgrade your openvpn package.


Solution : http://www.debian.org/security/2006/dsa-1045
Risk factor : High';

if (description) {
 script_id(22587);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1045");
 script_cve_id("CVE-2006-1629");
 script_bugtraq_id(17392);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1045] DSA-1045-1 openvpn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1045-1 openvpn");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'openvpn', release: '', reference: '2.0.6-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian .\nUpgrade to openvpn_2.0.6-1\n');
}
if (deb_check(prefix: 'openvpn', release: '3.1', reference: '2.0-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian 3.1.\nUpgrade to openvpn_2.0-1sarge3\n');
}
if (deb_check(prefix: 'openvpn', release: '3.1', reference: '2.0-1sarge3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian sarge.\nUpgrade to openvpn_2.0-1sarge3\n');
}
if (w) { security_hole(port: 0, data: desc); }
