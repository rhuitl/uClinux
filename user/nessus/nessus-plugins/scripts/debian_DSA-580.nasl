# This script was automatically generated from the dsa-580
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Faheem Mitha noticed that the iptables command, an administration tool
for IPv4 packet filtering and NAT, did not always load the required
modules on its own as it was supposed to.  This could lead to firewall
rules not being loaded on system startup.  This caused a failure in
connection with rules provided by lokkit at least.
For the stable distribution (woody) this problem has been fixed in
version 1.2.6a-5.0woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.2.11-4.
We recommend that you upgrade your iptables package.


Solution : http://www.debian.org/security/2004/dsa-580
Risk factor : High';

if (description) {
 script_id(15678);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "580");
 script_cve_id("CVE-2004-0986");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA580] DSA-580-1 iptables");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-580-1 iptables");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'iptables', release: '3.0', reference: '1.2.6a-5.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package iptables is vulnerable in Debian 3.0.\nUpgrade to iptables_1.2.6a-5.0woody2\n');
}
if (deb_check(prefix: 'iptables-dev', release: '3.0', reference: '1.2.6a-5.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package iptables-dev is vulnerable in Debian 3.0.\nUpgrade to iptables-dev_1.2.6a-5.0woody2\n');
}
if (deb_check(prefix: 'iptables', release: '3.1', reference: '1.2.11-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package iptables is vulnerable in Debian 3.1.\nUpgrade to iptables_1.2.11-4\n');
}
if (deb_check(prefix: 'iptables', release: '3.0', reference: '1.2.6a-5.0woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package iptables is vulnerable in Debian woody.\nUpgrade to iptables_1.2.6a-5.0woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
