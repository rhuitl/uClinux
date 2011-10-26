# This script was automatically generated from the dsa-965
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The Internet Key Exchange version 1 (IKEv1) implementation in racoon
from ipsec-tools, IPsec tools for Linux, try to dereference a NULL
pointer under certain conditions which allows a remote attacker to
cause a denial of service.
The old stable distribution (woody) does not contain ipsec-tools.
For the stable distribution (sarge) this problem has been fixed in
version 0.5.2-1sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.6.3-1.
We recommend that you upgrade your racoon package.


Solution : http://www.debian.org/security/2006/dsa-965
Risk factor : High';

if (description) {
 script_id(22831);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "965");
 script_cve_id("CVE-2005-3732");
 script_bugtraq_id(15523);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA965] DSA-965-1 ipsec-tools");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-965-1 ipsec-tools");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ipsec-tools', release: '', reference: '0.6.3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipsec-tools is vulnerable in Debian .\nUpgrade to ipsec-tools_0.6.3-1\n');
}
if (deb_check(prefix: 'ipsec-tools', release: '3.1', reference: '0.5.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipsec-tools is vulnerable in Debian 3.1.\nUpgrade to ipsec-tools_0.5.2-1sarge1\n');
}
if (deb_check(prefix: 'racoon', release: '3.1', reference: '0.5.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package racoon is vulnerable in Debian 3.1.\nUpgrade to racoon_0.5.2-1sarge1\n');
}
if (deb_check(prefix: 'ipsec-tools', release: '3.1', reference: '0.5.2-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ipsec-tools is vulnerable in Debian sarge.\nUpgrade to ipsec-tools_0.5.2-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
