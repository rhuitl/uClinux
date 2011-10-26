# This script was automatically generated from the dsa-490
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in the index support of the
ZCatalog plug-in in Zope, an open source web application server.  A
flaw in the security settings of ZCatalog allows anonymous users to
call arbitrary methods of catalog indexes.  The vulnerability also
allows untrusted code to do the same.
For the stable distribution (woody) this problem has been fixed in
version 2.5.1-1woody1.
For the unstable distribution (sid) this problem has been fixed in
version 2.6.0-0.1 and higher.
We recommend that you upgrade your zope package.


Solution : http://www.debian.org/security/2004/dsa-490
Risk factor : High';

if (description) {
 script_id(15327);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "490");
 script_cve_id("CVE-2002-0688");
 script_bugtraq_id(5812);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA490] DSA-490-1 zope");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-490-1 zope");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zope', release: '3.0', reference: '2.5.1-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope is vulnerable in Debian 3.0.\nUpgrade to zope_2.5.1-1woody1\n');
}
if (deb_check(prefix: 'zope', release: '3.1', reference: '2.6.0-0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope is vulnerable in Debian 3.1.\nUpgrade to zope_2.6.0-0\n');
}
if (deb_check(prefix: 'zope', release: '3.0', reference: '2.5.1-1woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope is vulnerable in Debian woody.\nUpgrade to zope_2.5.1-1woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
