# This script was automatically generated from the dsa-425
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Multiple vulnerabilities were discovered in tcpdump, a tool for
inspecting network traffic.  If a vulnerable version of tcpdump
attempted to examine a maliciously constructed packet, a number of
buffer overflows could be exploited to crash tcpdump, or potentially
execute arbitrary code with the privileges of the tcpdump process.
For the current stable distribution (woody) these problems have been
fixed in version 3.6.2-2.7.
For the unstable distribution (sid) these problems will be fixed soon.
We recommend that you update your tcpdump package.


Solution : http://www.debian.org/security/2004/dsa-425
Risk factor : High';

if (description) {
 script_id(15262);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0008");
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "425");
 script_cve_id("CVE-2003-0989", "CVE-2003-1029", "CVE-2004-0055", "CVE-2004-0057");
 script_bugtraq_id(9243, 9263, 9507);
 script_xref(name: "CERT", value: "174086");
 script_xref(name: "CERT", value: "738518");
 script_xref(name: "CERT", value: "955526");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA425] DSA-425-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-425-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.0.\nUpgrade to tcpdump_3.6.2-2.7\n');
}
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.7')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian woody.\nUpgrade to tcpdump_3.6.2-2.7\n');
}
if (w) { security_hole(port: 0, data: desc); }
