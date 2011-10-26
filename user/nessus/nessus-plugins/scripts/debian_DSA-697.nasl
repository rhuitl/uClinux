# This script was automatically generated from the dsa-697
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Gaël Delalleau discovered a buffer overflow in the handling of
the LINEMODE suboptions in telnet clients.  This can lead to the
execution of arbitrary code when connected to a malicious server.
For the stable distribution (woody) this problem has been fixed in
version 0.17-18woody3.
For the unstable distribution (sid) this problem has been fixed in
version 0.17-28.
We recommend that you upgrade your telnet package.


Solution : http://www.debian.org/security/2005/dsa-697
Risk factor : High';

if (description) {
 script_id(17639);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "697");
 script_cve_id("CVE-2005-0469");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA697] DSA-697-1 netkit-telnet");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-697-1 netkit-telnet");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'telnet', release: '3.0', reference: '0.17-18woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package telnet is vulnerable in Debian 3.0.\nUpgrade to telnet_0.17-18woody3\n');
}
if (deb_check(prefix: 'telnetd', release: '3.0', reference: '0.17-18woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package telnetd is vulnerable in Debian 3.0.\nUpgrade to telnetd_0.17-18woody3\n');
}
if (deb_check(prefix: 'netkit-telnet', release: '3.1', reference: '0.17-28')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netkit-telnet is vulnerable in Debian 3.1.\nUpgrade to netkit-telnet_0.17-28\n');
}
if (deb_check(prefix: 'netkit-telnet', release: '3.0', reference: '0.17-18woody3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netkit-telnet is vulnerable in Debian woody.\nUpgrade to netkit-telnet_0.17-18woody3\n');
}
if (w) { security_hole(port: 0, data: desc); }
