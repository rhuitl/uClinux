# This script was automatically generated from the dsa-849
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"Supernaut" noticed that shorewall, the Shoreline Firewall, could
generate an iptables configuration which is significantly more
permissive than the rule set given in the shorewall configuration, if
MAC verification are used in a non-default manner.
When MACLIST_DISPOSITION is set to ACCEPT in the shorewall.conf file,
all packets from hosts which fail the MAC verification pass through
the firewall, without further checks.  When MACLIST_TTL is set to a
non-zero value, packets from hosts which pass the MAC verification
pass through the firewall, again without further checks.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.3-2.
For the unstable distribution (sid) this problem has been fixed in
version 2.4.1-2.
We recommend that you upgrade your shorewall package.


Solution : http://www.debian.org/security/2005/dsa-849
Risk factor : High';

if (description) {
 script_id(19957);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "849");
 script_cve_id("CVE-2005-2317");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA849] DSA-849-1 shorewall");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-849-1 shorewall");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'shorewall', release: '', reference: '2.4.1-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package shorewall is vulnerable in Debian .\nUpgrade to shorewall_2.4.1-2\n');
}
if (deb_check(prefix: 'shorewall', release: '3.1', reference: '2.2.3-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package shorewall is vulnerable in Debian 3.1.\nUpgrade to shorewall_2.2.3-2\n');
}
if (deb_check(prefix: 'shorewall', release: '3.1', reference: '2.2.3-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package shorewall is vulnerable in Debian sarge.\nUpgrade to shorewall_2.2.3-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
