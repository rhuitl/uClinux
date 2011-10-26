# This script was automatically generated from the dsa-330
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
tcptraceroute is a setuid-root program which drops root privileges
after obtaining a file descriptor used for raw packet capture.
However, it did not fully relinquish all privileges, and in the event
of an exploitable vulnerability, root privileges could be regained.
No current exploit is known, but this safeguard is being repaired in
order to provide a measure of containment in the event that an
exploitable flaw should be discovered.
For the stable distribution (woody) this problem has been fixed in
version 1.2-2.
The old stable distribution (potato) does not contain a tcptraceroute
package.
For the unstable distribution (sid) this problem is fixed in version
1.4-4.
We recommend that you update your tcptraceroute package.


Solution : http://www.debian.org/security/2003/dsa-330
Risk factor : High';

if (description) {
 script_id(15167);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "330");
 script_cve_id("CVE-2003-0489");
 script_bugtraq_id(8020);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA330] DSA-330-1 tcptraceroute");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-330-1 tcptraceroute");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tcptraceroute', release: '3.0', reference: '1.2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcptraceroute is vulnerable in Debian 3.0.\nUpgrade to tcptraceroute_1.2-2\n');
}
if (deb_check(prefix: 'tcptraceroute', release: '3.1', reference: '1.4-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcptraceroute is vulnerable in Debian 3.1.\nUpgrade to tcptraceroute_1.4-4\n');
}
if (deb_check(prefix: 'tcptraceroute', release: '3.0', reference: '1.2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcptraceroute is vulnerable in Debian woody.\nUpgrade to tcptraceroute_1.2-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
