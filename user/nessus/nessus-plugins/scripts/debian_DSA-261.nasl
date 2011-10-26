# This script was automatically generated from the dsa-261
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in tcpdump, a powerful tool for network
monitoring and data acquisition.  An attacker is able to send a
specially crafted RADIUS network packet which causes tcpdump to enter
an infinite loop.
For the stable distribution (woody) this problem has been
fixed in version 3.6.2-2.4.
The old stable distribution (potato) does not seem to be affected
by this problem.
The unstable distribution (sid) is not affected by this problem anymore.
We recommend that you upgrade your tcpdump package.


Solution : http://www.debian.org/security/2003/dsa-261
Risk factor : High';

if (description) {
 script_id(15098);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "261");
 script_cve_id("CVE-2003-0093", "CVE-2003-0145");
 script_bugtraq_id(7090);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA261] DSA-261-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-261-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.0.\nUpgrade to tcpdump_3.6.2-2.4\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian woody.\nUpgrade to tcpdump_3.6.2-2.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
