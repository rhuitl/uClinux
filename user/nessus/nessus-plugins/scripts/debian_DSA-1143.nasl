# This script was automatically generated from the dsa-1143
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Justin Winschief and Andrew Steets discovered a bug in dhcp, the DHCP
server for automatic IP address assignment, which causes the server to
unexpectedly exit.
For the stable distribution (sarge) this problem has been fixed in
version 2.0pl5-19.1sarge2.
For the unstable distribution (sid) this problem will be fixed soon.
We recommend that you upgrade your dhcp package.


Solution : http://www.debian.org/security/2006/dsa-1143
Risk factor : High';

if (description) {
 script_id(22685);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1143");
 script_cve_id("CVE-2006-3122");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1143] DSA-1143-1 dhcp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1143-1 dhcp");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dhcp', release: '3.1', reference: '2.0pl5-19.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp is vulnerable in Debian 3.1.\nUpgrade to dhcp_2.0pl5-19.1sarge2\n');
}
if (deb_check(prefix: 'dhcp-client', release: '3.1', reference: '2.0pl5-19.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp-client is vulnerable in Debian 3.1.\nUpgrade to dhcp-client_2.0pl5-19.1sarge2\n');
}
if (deb_check(prefix: 'dhcp-relay', release: '3.1', reference: '2.0pl5-19.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp-relay is vulnerable in Debian 3.1.\nUpgrade to dhcp-relay_2.0pl5-19.1sarge2\n');
}
if (deb_check(prefix: 'dhcp', release: '3.1', reference: '2.0pl5-19.1sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp is vulnerable in Debian sarge.\nUpgrade to dhcp_2.0pl5-19.1sarge2\n');
}
if (w) { security_hole(port: 0, data: desc); }
