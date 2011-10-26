# This script was automatically generated from the dsa-255
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Andrew Griffiths and iDEFENSE Labs discovered a problem in tcpdump, a
powerful tool for network monitoring and data acquisition.  An
attacker is able to send a specially crafted network packet which
causes tcpdump to enter an infinite loop.
In addition to the above problem the tcpdump developers discovered a
potential infinite loop when parsing malformed BGP packets.  They also
discovered a buffer overflow that can be exploited with certain
malformed NFS packets.
For the stable distribution (woody) these problems have been
fixed in version 3.6.2-2.3.
The old stable distribution (potato) does not seem to be affected
by these problems.
For the unstable distribution (sid) these problems have been fixed in
version 3.7.1-1.2.
We recommend that you upgrade your tcpdump packages.


Solution : http://www.debian.org/security/2003/dsa-255
Risk factor : High';

if (description) {
 script_id(15092);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "255");
 script_cve_id("CVE-2003-0108", "CVE-2002-0380");
 script_bugtraq_id(4890, 6974);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA255] DSA-255-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-255-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.0.\nUpgrade to tcpdump_3.6.2-2.3\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.1', reference: '3.7.1-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.1.\nUpgrade to tcpdump_3.7.1-1.2\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian woody.\nUpgrade to tcpdump_3.6.2-2.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
