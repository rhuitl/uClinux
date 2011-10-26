# This script was automatically generated from the dsa-534
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A directory traversal vulnerability was discovered in mailreader
whereby remote attackers could view arbitrary files with the
privileges of the nph-mr.cgi process (by default, www-data) via
relative paths and a null byte in the configLanguage parameter.
For the current stable distribution (woody), this problem has been
fixed in version 2.3.29-5woody1.
For the unstable distribution (sid), this problem will be fixed soon.
We recommend that you update your mailreader package.


Solution : http://www.debian.org/security/2004/dsa-534
Risk factor : High';

if (description) {
 script_id(15371);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "534");
 script_cve_id("CVE-2002-1581");
 script_bugtraq_id(6055);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA534] DSA-534-1 mailreader");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-534-1 mailreader");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'mailreader', release: '3.0', reference: '2.3.29-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailreader is vulnerable in Debian 3.0.\nUpgrade to mailreader_2.3.29-5woody1\n');
}
if (deb_check(prefix: 'mailreader', release: '3.0', reference: '2.3.29-5woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mailreader is vulnerable in Debian woody.\nUpgrade to mailreader_2.3.29-5woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
