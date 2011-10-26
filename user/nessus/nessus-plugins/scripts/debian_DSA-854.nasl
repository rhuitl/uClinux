# This script was automatically generated from the dsa-854
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Simon Nielsen discovered that the BGP dissector in tcpdump, a powerful
tool for network monitoring and data acquisition, does not properly
handle a -1 return value from an internal function that decodes data
packets.  A specially crafted BGP packet can cause a denial of service
via an infinite loop.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 3.8.3-5sarge1.
We recommend that you upgrade your tcpdump package.


Solution : http://www.debian.org/security/2005/dsa-854
Risk factor : High';

if (description) {
 script_id(19962);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "854");
 script_cve_id("CVE-2005-1267");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA854] DSA-854-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-854-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tcpdump', release: '3.1', reference: '3.8.3-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.1.\nUpgrade to tcpdump_3.8.3-5sarge1\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.1', reference: '3.8.3-5sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian sarge.\nUpgrade to tcpdump_3.8.3-5sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
