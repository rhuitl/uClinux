# This script was automatically generated from the dsa-254
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in NANOG traceroute, an enhanced
version of the Van Jacobson/BSD traceroute program.  A buffer overflow
occurs in the \'get_origin()\' function.  Due to insufficient bounds
checking performed by the whois parser, it may be possible to corrupt
memory on the system stack.  This vulnerability can be exploited by a
remote attacker to gain root privileges on a target host.  Though,
most probably not in Debian.
The Common Vulnerabilities and Exposures (CVE) project additionally
identified the following vulnerabilities which were already fixed in
the Debian version in stable (woody) and oldstable (potato) and are
mentioned here for completeness (and since other distributions had to
release a separate advisory for them):
Fortunately, the Debian package drops privileges quite early after
startup, so those problems are not likely to result in an exploit on a
Debian machine.
For the current stable distribution (woody) the above problem has been
fixed in version 6.1.1-1.2.
For the old stable distribution (potato) the above problem has been
fixed in version 6.0-2.2.
For the unstable distribution (sid) these problems have been fixed in
version 6.3.0-1.
We recommend that you upgrade your traceroute-nanog package.


Solution : http://www.debian.org/security/2003/dsa-254
Risk factor : High';

if (description) {
 script_id(15091);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "254");
 script_cve_id("CVE-2002-1386", "CVE-2002-1387", "CVE-2002-1051", "CVE-2002-1364");
 script_bugtraq_id(4956, 6166, 6274, 6275);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA254] DSA-254-1 traceroute-nanog");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-254-1 traceroute-nanog");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'traceroute-nanog', release: '2.2', reference: '6.0-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package traceroute-nanog is vulnerable in Debian 2.2.\nUpgrade to traceroute-nanog_6.0-2.2\n');
}
if (deb_check(prefix: 'traceroute-nanog', release: '3.0', reference: '6.1.1-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package traceroute-nanog is vulnerable in Debian 3.0.\nUpgrade to traceroute-nanog_6.1.1-1.2\n');
}
if (deb_check(prefix: 'traceroute-nanog', release: '3.1', reference: '6.3.0-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package traceroute-nanog is vulnerable in Debian 3.1.\nUpgrade to traceroute-nanog_6.3.0-1\n');
}
if (deb_check(prefix: 'traceroute-nanog', release: '2.2', reference: '6.0-2.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package traceroute-nanog is vulnerable in Debian potato.\nUpgrade to traceroute-nanog_6.0-2.2\n');
}
if (deb_check(prefix: 'traceroute-nanog', release: '3.0', reference: '6.1.1-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package traceroute-nanog is vulnerable in Debian woody.\nUpgrade to traceroute-nanog_6.1.1-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
