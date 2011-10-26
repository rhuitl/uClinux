# This script was automatically generated from the dsa-1122
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Peter Bieringer discovered that the "log" function in the Net::Server
Perl module, an extensible, general perl server engine, is not safe
against format string exploits.
The old stable distribution (woody) does not contain this package.
For the stable distribution (sarge) this problem has been fixed in
version 0.87-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.89-1.
We recommend that you upgrade your libnet-server-perl package.


Solution : http://www.debian.org/security/2006/dsa-1122
Risk factor : High';

if (description) {
 script_id(22664);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1122");
 script_cve_id("CVE-2005-1127");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1122] DSA-1122-1 libnet-server-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1122-1 libnet-server-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libnet-server-perl', release: '', reference: '0.89-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnet-server-perl is vulnerable in Debian .\nUpgrade to libnet-server-perl_0.89-1\n');
}
if (deb_check(prefix: 'libnet-server-perl', release: '3.1', reference: '0.87-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnet-server-perl is vulnerable in Debian 3.1.\nUpgrade to libnet-server-perl_0.87-3sarge1\n');
}
if (deb_check(prefix: 'libnet-server-perl', release: '3.1', reference: '0.87-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libnet-server-perl is vulnerable in Debian sarge.\nUpgrade to libnet-server-perl_0.87-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
