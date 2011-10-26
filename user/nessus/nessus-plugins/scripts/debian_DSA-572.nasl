# This script was automatically generated from the dsa-572
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in ecartis, a mailing-list manager,
which allows an attacker in the same domain as the list admin to gain
administrator privileges and alter list settings.
For the stable distribution (woody) this problem has been fixed in
version 0.129a+1.0.0-snap20020514-1.3.
For the unstable distribution (sid) this problem has been fixed in
version 1.0.0+cvs.20030911-8.
We recommend that you upgrade your ecartis package.


Solution : http://www.debian.org/security/2004/dsa-572
Risk factor : High';

if (description) {
 script_id(15670);
 script_version("$Revision: 1.4 $");
 script_xref(name: "DSA", value: "572");
 script_cve_id("CVE-2004-0913");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA572] DSA-572-1 ecartis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-572-1 ecartis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ecartis', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis is vulnerable in Debian 3.0.\nUpgrade to ecartis_0.129a+1.0.0-snap20020514-1.3\n');
}
if (deb_check(prefix: 'ecartis-cgi', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis-cgi is vulnerable in Debian 3.0.\nUpgrade to ecartis-cgi_0.129a+1.0.0-snap20020514-1.3\n');
}
if (deb_check(prefix: 'ecartis', release: '3.1', reference: '1.0.0+cvs.20030911-8')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis is vulnerable in Debian 3.1.\nUpgrade to ecartis_1.0.0+cvs.20030911-8\n');
}
if (deb_check(prefix: 'ecartis', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis is vulnerable in Debian woody.\nUpgrade to ecartis_0.129a+1.0.0-snap20020514-1.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
