# This script was automatically generated from the dsa-850
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"Vade 79" discovered that the BGP dissector in tcpdump, a powerful
tool for network monitoring and data acquisition, does not properly
handle RT_ROUTING_INFO.  A specially crafted BGP packet can cause a
denial of service via an infinite loop.
For the old stable distribution (woody) this problem has been fixed in
version 3.6.2-2.9.
For the stable distribution (sarge) this problem has been fixed in
version 3.8.3-4.
For the unstable distribution (sid) this problem has been fixed in
version 3.8.3-4.
We recommend that you upgrade your tcpdump package.


Solution : http://www.debian.org/security/2005/dsa-850
Risk factor : High';

if (description) {
 script_id(19958);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "850");
 script_cve_id("CVE-2005-1279");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA850] DSA-850-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-850-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.0.\nUpgrade to tcpdump_3.6.2-2.9\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.1', reference: '3.8.3-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.1.\nUpgrade to tcpdump_3.8.3-4\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.1', reference: '3.8.3-4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian sarge.\nUpgrade to tcpdump_3.8.3-4\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian woody.\nUpgrade to tcpdump_3.6.2-2.9\n');
}
if (w) { security_hole(port: 0, data: desc); }
