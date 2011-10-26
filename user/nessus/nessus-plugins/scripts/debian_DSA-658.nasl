# This script was automatically generated from the dsa-658
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña from the Debian Security Audit Project
discovered that the DBI library, the Perl5 database interface, creates
a temporary PID file in an insecure manner.  This can be exploited by a
malicious user to overwrite arbitrary files owned by the person
executing the parts of the library.
For the stable distribution (woody) this problem has been fixed in
version 1.21-2woody2.
For the unstable distribution (sid) this problem has been fixed in
version 1.46-6.
We recommend that you upgrade your libdbi-perl package.


Solution : http://www.debian.org/security/2005/dsa-658
Risk factor : High';

if (description) {
 script_id(16249);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "658");
 script_cve_id("CVE-2005-0077");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA658] DSA-658-1 libdbi-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-658-1 libdbi-perl");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libdbi-perl', release: '3.0', reference: '1.21-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdbi-perl is vulnerable in Debian 3.0.\nUpgrade to libdbi-perl_1.21-2woody2\n');
}
if (deb_check(prefix: 'libdbi-perl', release: '3.1', reference: '1.46-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdbi-perl is vulnerable in Debian 3.1.\nUpgrade to libdbi-perl_1.46-6\n');
}
if (deb_check(prefix: 'libdbi-perl', release: '3.0', reference: '1.21-2woody2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libdbi-perl is vulnerable in Debian woody.\nUpgrade to libdbi-perl_1.21-2woody2\n');
}
if (w) { security_hole(port: 0, data: desc); }
