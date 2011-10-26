# This script was automatically generated from the dsa-318
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Calle Dybedahl discovered a bug in lyskom-server which could result in
a denial of service where an unauthenticated user could cause the
server to become unresponsive as it processes a large query.
For the stable distribution (woody) this problem has been fixed in
version 2.0.6-1woody1.
The old stable distribution (potato) does not contain a lyskom-server package.
For the unstable distribution (sid) this problem is fixed in version
2.0.7-2.
We recommend that you update your lyskom-server package.


Solution : http://www.debian.org/security/2003/dsa-318
Risk factor : High';

if (description) {
 script_id(15155);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "318");
 script_cve_id("CVE-2003-0366");
 script_bugtraq_id(7893);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA318] DSA-318-1 lyskom-server");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-318-1 lyskom-server");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'lyskom-server', release: '3.0', reference: '2.0.6-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lyskom-server is vulnerable in Debian 3.0.\nUpgrade to lyskom-server_2.0.6-1woody1\n');
}
if (deb_check(prefix: 'lyskom-server', release: '3.1', reference: '2.0.7-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lyskom-server is vulnerable in Debian 3.1.\nUpgrade to lyskom-server_2.0.7-2\n');
}
if (deb_check(prefix: 'lyskom-server', release: '3.0', reference: '2.0.6-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package lyskom-server is vulnerable in Debian woody.\nUpgrade to lyskom-server_2.0.6-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
