# This script was automatically generated from the dsa-832
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several buffer overflows have been discovered in gopher, a
text-oriented client for the Gopher Distributed Hypertext protocol,
that can be exploited by a malicious Gopher server.
For the old stable distribution (woody) this problem has been fixed in
version 3.0.3woody4.
For the stable distribution (sarge) this problem has been fixed in
version 3.0.7sarge2.
For the unstable distribution (sid) this problem has been fixed in
version 3.0.11.
We recommend that you upgrade your gopher package.


Solution : http://www.debian.org/security/2005/dsa-832
Risk factor : High';

if (description) {
 script_id(19801);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "832");
 script_cve_id("CVE-2005-2772");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA832] DSA-832-1 gopher");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-832-1 gopher");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gopher', release: '', reference: '3.0.11')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian .\nUpgrade to gopher_3.0.11\n');
}
if (deb_check(prefix: 'gopher', release: '3.0', reference: '3.0.3woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian 3.0.\nUpgrade to gopher_3.0.3woody4\n');
}
if (deb_check(prefix: 'gopherd', release: '3.0', reference: '3.0.3woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopherd is vulnerable in Debian 3.0.\nUpgrade to gopherd_3.0.3woody4\n');
}
if (deb_check(prefix: 'gopher', release: '3.1', reference: '3.0.7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian 3.1.\nUpgrade to gopher_3.0.7sarge2\n');
}
if (deb_check(prefix: 'gopher', release: '3.1', reference: '3.0.7sarge2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian sarge.\nUpgrade to gopher_3.0.7sarge2\n');
}
if (deb_check(prefix: 'gopher', release: '3.0', reference: '3.0.3woody4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gopher is vulnerable in Debian woody.\nUpgrade to gopher_3.0.3woody4\n');
}
if (w) { security_hole(port: 0, data: desc); }
