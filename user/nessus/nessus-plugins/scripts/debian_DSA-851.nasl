# This script was automatically generated from the dsa-851
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several security related problems have been discovered in openvpn, a
Virtual Private Network daemon.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Wrong processing of failed certificate authentication when running
    with "verb 0" and without TLS authentication can lead to a denial
    of service by disconnecting the wrong client.
    Wrong handling of packets that can\'t be decrypted on the server
    can lead to the disconnection of unrelated clients.
    When running in "dev tap" Ethernet bridging mode, openvpn can
    exhaust its memory by receiving a large number of spoofed MAC
    addresses and hence denying service.
    Simultaneous TCP connections from multiple clients with the same
    client certificate can cause a denial of service when
    --duplicate-cn is not enabled.
The old stable distribution (woody) does not contain openvpn packages.
For the stable distribution (sarge) these problems have been fixed in
version 2.0-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.2-1.
We recommend that you upgrade your openvpn package.


Solution : http://www.debian.org/security/2005/dsa-851
Risk factor : High';

if (description) {
 script_id(19959);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "851");
 script_cve_id("CVE-2005-2531", "CVE-2005-2532", "CVE-2005-2533", "CVE-2005-2534");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA851] DSA-851-1 openvpn");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-851-1 openvpn");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'openvpn', release: '', reference: '2.0.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian .\nUpgrade to openvpn_2.0.2-1\n');
}
if (deb_check(prefix: 'openvpn', release: '3.1', reference: '2.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian 3.1.\nUpgrade to openvpn_2.0-1sarge1\n');
}
if (deb_check(prefix: 'openvpn', release: '3.1', reference: '2.0-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openvpn is vulnerable in Debian sarge.\nUpgrade to openvpn_2.0-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
