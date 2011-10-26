# This script was automatically generated from the dsa-885
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in OpenVPN, a free
virtual private network daemon.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    A format string vulnerability has been discovered that could allow
    arbitrary code to be executed on the client.
    A NULL pointer dereferencing has been discovered that could be
    exploited to crash the service.
The old stable distribution (woody) does not contain openvpn packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.0-1sarge2.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.5-1.
We recommend that you upgrade your openvpn package.


Solution : http://www.debian.org/security/2005/dsa-885
Risk factor : High';

if (description) {
 script_id(22751);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "885");
 script_cve_id("CVE-2005-3393", "CVE-2005-3409");
 script_bugtraq_id(15239);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA885] DSA-885-1 openvpn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-885-1 openvpn");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'openvpn', release: '', reference: '2.0.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian .\nUpgrade to openvpn_2.0.5-1\n');
}
if (deb_check(prefix: 'openvpn', release: '3.1', reference: '2.0-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian 3.1.\nUpgrade to openvpn_2.0-1sarge2\n');
}
if (deb_check(prefix: 'openvpn', release: '3.1', reference: '2.0-1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian sarge.\nUpgrade to openvpn_2.0-1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
