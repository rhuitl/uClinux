# This script was automatically generated from the dsa-556
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Michal Zalewski discovered a bug in the netkit-telnet server (telnetd)
whereby a remote attacker could cause the telnetd process to free an
invalid pointer.  This causes the telnet server process to crash,
leading to a straightforward denial of service (inetd will disable the
service if telnetd is crashed repeatedly), or possibly the execution
of arbitrary code with the privileges of the telnetd process (by
default, the \'telnetd\' user).
For the stable distribution (woody) this problem has been fixed in
version 0.17-18woody2.
For the unstable distribution (sid) this problem has been fixed in
version 0.17-26.
We recommend that you upgrade your netkit-telnet package.


Solution : http://www.debian.org/security/2004/dsa-556
Risk factor : High';

if (description) {
 script_id(15654);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "556");
 script_cve_id("CVE-2004-0911");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA556] DSA-556-2 netkit-telnet");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-556-2 netkit-telnet");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'telnet', release: '3.0', reference: '0.17-18woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package telnet is vulnerable in Debian 3.0.\nUpgrade to telnet_0.17-18woody2\n');
}
if (deb_check(prefix: 'telnetd', release: '3.0', reference: '0.17-18woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package telnetd is vulnerable in Debian 3.0.\nUpgrade to telnetd_0.17-18woody2\n');
}
if (deb_check(prefix: 'netkit-telnet', release: '3.1', reference: '0.17-26')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netkit-telnet is vulnerable in Debian 3.1.\nUpgrade to netkit-telnet_0.17-26\n');
}
if (deb_check(prefix: 'netkit-telnet', release: '3.0', reference: '0.17-18woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package netkit-telnet is vulnerable in Debian woody.\nUpgrade to netkit-telnet_0.17-18woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
