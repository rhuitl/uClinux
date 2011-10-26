# This script was automatically generated from the dsa-478
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
tcpdump, a tool for network monitoring and data acquisition, was found
to contain two vulnerabilities whereby tcpdump could be caused to
crash through attempts to read from invalid memory locations.  This
bug is triggered by certain invalid ISAKMP packets.
For the current stable distribution (woody) these problems have been
fixed in version 3.6.2-2.8.
For the unstable distribution (sid), these problems have been fixed in
version 3.7.2-4.
We recommend that you update your tcpdump package.


Solution : http://www.debian.org/security/2004/dsa-478
Risk factor : High';

if (description) {
 script_id(15315);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "478");
 script_cve_id("CVE-2004-0183", "CVE-2004-0184");
 script_bugtraq_id(10003, 10003, 10004, 10004);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA478] DSA-478-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-478-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.0.\nUpgrade to tcpdump_3.6.2-2.8\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.1', reference: '3.7.2-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.1.\nUpgrade to tcpdump_3.7.2-4\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian woody.\nUpgrade to tcpdump_3.6.2-2.8\n');
}
if (w) { security_hole(port: 0, data: desc); }
