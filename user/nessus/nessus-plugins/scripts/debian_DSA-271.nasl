# This script was automatically generated from the dsa-271
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem has been discovered in ecartis, a mailing list manager,
formerly known as listar.  This vulnerability enables an attacker to
reset the password of any user defined on the list server, including
the list admins.
For the stable distribution (woody) this problem has been fixed in
version 0.129a+1.0.0-snap20020514-1.1 of ecartis.
For the old stable distribution (potato) this problem has been fixed
in version 0.129a-2.potato3 of listar.
For the unstable distribution (sid) this problem has been
fixed in version 1.0.0+cvs.20030321-1 of ecartis.
We recommend that you upgrade your ecartis and listar packages.


Solution : http://www.debian.org/security/2003/dsa-271
Risk factor : High';

if (description) {
 script_id(15108);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "271");
 script_cve_id("CVE-2003-0162");
 script_bugtraq_id(6971);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA271] DSA-271-1 ecartis");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-271-1 ecartis");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'listar', release: '2.2', reference: '0.129a-2.potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package listar is vulnerable in Debian 2.2.\nUpgrade to listar_0.129a-2.potato3\n');
}
if (deb_check(prefix: 'listar-cgi', release: '2.2', reference: '0.129a-2.potato3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package listar-cgi is vulnerable in Debian 2.2.\nUpgrade to listar-cgi_0.129a-2.potato3\n');
}
if (deb_check(prefix: 'ecartis', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis is vulnerable in Debian 3.0.\nUpgrade to ecartis_0.129a+1.0.0-snap20020514-1.1\n');
}
if (deb_check(prefix: 'ecartis-cgi', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis-cgi is vulnerable in Debian 3.0.\nUpgrade to ecartis-cgi_0.129a+1.0.0-snap20020514-1.1\n');
}
if (deb_check(prefix: 'ecartis,', release: '3.1', reference: '1.0.0+cvs')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis, is vulnerable in Debian 3.1.\nUpgrade to ecartis,_1.0.0+cvs\n');
}
if (deb_check(prefix: 'ecartis,', release: '2.2', reference: '0.129a-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis, is vulnerable in Debian potato.\nUpgrade to ecartis,_0.129a-2\n');
}
if (deb_check(prefix: 'ecartis,', release: '3.0', reference: '0.129a+1.0.0-snap20020514-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ecartis, is vulnerable in Debian woody.\nUpgrade to ecartis,_0.129a+1.0.0-snap20020514-1\n');
}
if (w) { security_hole(port: 0, data: desc); }
