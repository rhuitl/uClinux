# This script was automatically generated from the dsa-245
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Florian Lohoff discovered a bug in the dhcrelay causing it to send a
continuing packet storm towards the configured DHCP server(s) in case
of a malicious BOOTP packet, such as sent from buggy Cisco switches.
When the dhcp-relay receives a BOOTP request it forwards the request
to the DHCP server using the broadcast MAC address ff:ff:ff:ff:ff:ff
which causes the network interface to reflect the packet back into the
socket.  To prevent loops the dhcrelay checks whether the
relay-address is its own, in which case the packet would be dropped.
In combination with a missing upper boundary for the hop counter an
attacker can force the dhcp-relay to send a continuing packet storm
towards the configured dhcp server(s).
This patch introduces a new command line switch -c maxcount and
people are advised to start the dhcp-relay with dhcrelay -c 10
or a smaller number, which will only create that many packets.
The dhcrelay program from the "dhcp" package does not seem to be
affected since DHCP packets are dropped if they were apparently
relayed already.
For the stable distribution (woody) this problem has been fixed in
version 3.0+3.0.1rc9-2.2.
The old stable distribution (potato) does not contain dhcp3 packages.
For the unstable distribution (sid) this problem has been fixed in
version 1.1.2-1.
We recommend that you upgrade your dhcp3 package when you are using
the dhcrelay server.


Solution : http://www.debian.org/security/2003/dsa-245
Risk factor : High';

if (description) {
 script_id(15082);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "245");
 script_cve_id("CVE-2003-0039");
 script_bugtraq_id(6628);
 script_xref(name: "CERT", value: "149953");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA245] DSA-245-1 dhcp3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-245-1 dhcp3");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'dhcp3-client', release: '3.0', reference: '3.0+3.0.1rc9-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-client is vulnerable in Debian 3.0.\nUpgrade to dhcp3-client_3.0+3.0.1rc9-2.2\n');
}
if (deb_check(prefix: 'dhcp3-common', release: '3.0', reference: '3.0+3.0.1rc9-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-common is vulnerable in Debian 3.0.\nUpgrade to dhcp3-common_3.0+3.0.1rc9-2.2\n');
}
if (deb_check(prefix: 'dhcp3-dev', release: '3.0', reference: '3.0+3.0.1rc9-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-dev is vulnerable in Debian 3.0.\nUpgrade to dhcp3-dev_3.0+3.0.1rc9-2.2\n');
}
if (deb_check(prefix: 'dhcp3-relay', release: '3.0', reference: '3.0+3.0.1rc9-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-relay is vulnerable in Debian 3.0.\nUpgrade to dhcp3-relay_3.0+3.0.1rc9-2.2\n');
}
if (deb_check(prefix: 'dhcp3-server', release: '3.0', reference: '3.0+3.0.1rc9-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3-server is vulnerable in Debian 3.0.\nUpgrade to dhcp3-server_3.0+3.0.1rc9-2.2\n');
}
if (deb_check(prefix: 'dhcp3', release: '3.1', reference: '1.1.2-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3 is vulnerable in Debian 3.1.\nUpgrade to dhcp3_1.1.2-1\n');
}
if (deb_check(prefix: 'dhcp3', release: '3.0', reference: '3.0+3.0.1rc9-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package dhcp3 is vulnerable in Debian woody.\nUpgrade to dhcp3_3.0+3.0.1rc9-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
