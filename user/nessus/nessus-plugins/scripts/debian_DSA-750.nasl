# This script was automatically generated from the dsa-750
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"infamous42md" discovered that dhcpcd, a DHCP client for automatically
configuring IPv4 networking, can be tricked into reading past the end
of the supplied DHCP buffer which could lead to the daemon crashing.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 1.3.22pl4-21sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.3.22pl4-22.
We recommend that you upgrade your dhcpcd package.


Solution : http://www.debian.org/security/2005/dsa-750
Risk factor : High';

if (description) {
 script_id(18665);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "750");
 script_cve_id("CVE-2005-1848");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA750] DSA-750-1 dhcpcd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-750-1 dhcpcd");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dhcpcd', release: '', reference: '1.3.22pl4-22')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcpcd is vulnerable in Debian .\nUpgrade to dhcpcd_1.3.22pl4-22\n');
}
if (deb_check(prefix: 'dhcpcd', release: '3.1', reference: '1.3.22pl4-21sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcpcd is vulnerable in Debian 3.1.\nUpgrade to dhcpcd_1.3.22pl4-21sarge1\n');
}
if (deb_check(prefix: 'dhcpcd', release: '3.1', reference: '1.3.22pl4-21sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcpcd is vulnerable in Debian sarge.\nUpgrade to dhcpcd_1.3.22pl4-21sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
