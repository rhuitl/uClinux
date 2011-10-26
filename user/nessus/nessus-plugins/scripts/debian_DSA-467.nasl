# This script was automatically generated from the dsa-467
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Timo Sirainen discovered two vulnerabilities in ecartis, a mailing
list manager.
   Failure to validate user input could lead to
   disclosure of mailing list passwords
   Multiple buffer overflows
For the stable distribution (woody) these problems have been fixed in
version 0.129a+1.0.0-snap20020514-1.2.
For the unstable distribution (sid) these problems have been fixed in
version 1.0.0+cvs.20030911.
We recommend that you update your ecartis package.


Solution : http://www.debian.org/security/2004/dsa-467
Risk factor : High';

if (description) {
 script_id(15304);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "467");
 script_cve_id("CVE-2003-0781", "CVE-2003-0782");
 script_bugtraq_id(8420, 8421);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA467] DSA-467-1 ecartis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-467-1 ecartis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ecartis', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis is vulnerable in Debian 3.0.\nUpgrade to ecartis_0.129a+1.0.0-snap20020514-1.2\n');
}
if (deb_check(prefix: 'ecartis-cgi', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis-cgi is vulnerable in Debian 3.0.\nUpgrade to ecartis-cgi_0.129a+1.0.0-snap20020514-1.2\n');
}
if (deb_check(prefix: 'ecartis', release: '3.1', reference: '1.0.0+cvs.20030911')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis is vulnerable in Debian 3.1.\nUpgrade to ecartis_1.0.0+cvs.20030911\n');
}
if (deb_check(prefix: 'ecartis', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis is vulnerable in Debian woody.\nUpgrade to ecartis_0.129a+1.0.0-snap20020514-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
