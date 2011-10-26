# This script was automatically generated from the dsa-206
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
The BGP decoding routines for tcpdump used incorrect bounds checking
when copying data. This could be abused by introducing malicious traffic
on a sniffed network for a denial of service attack against tcpdump,
or possibly even remote code execution.
This has been fixed in version 3.6.2-2.2.


Solution : http://www.debian.org/security/2002/dsa-206
Risk factor : High';

if (description) {
 script_id(15043);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "206");
 script_cve_id("CVE-2002-1350");
 script_bugtraq_id(6213);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA206] DSA-206-1 tcpdump");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-206-1 tcpdump");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'tcpdump', release: '3.0', reference: '3.6.2-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package tcpdump is vulnerable in Debian 3.0.\nUpgrade to tcpdump_3.6.2-2.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
