# This script was automatically generated from the dsa-910
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A vulnerability has been discovered in zope 2.7, an Open Source web
application server, that allows remote attackers to insert arbitrary
files via include directives in reStructuredText functionality.
The old stable distribution (woody) does not contain zope2.7 packages.
For the stable distribution (sarge) this problem has been fixed in
version 2.7.5-2sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.7.8-1.
We recommend that you upgrade your zope2.7 package.


Solution : http://www.debian.org/security/2005/dsa-910
Risk factor : High';

if (description) {
 script_id(22776);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "910");
 script_cve_id("CVE-2005-3323");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA910] DSA-910-1 zope.2.7");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-910-1 zope.2.7");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zope2.7', release: '', reference: '2.7.8-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope2.7 is vulnerable in Debian .\nUpgrade to zope2.7_2.7.8-1\n');
}
if (deb_check(prefix: 'zope2.7', release: '3.1', reference: '2.7.5-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope2.7 is vulnerable in Debian 3.1.\nUpgrade to zope2.7_2.7.5-2sarge1\n');
}
if (deb_check(prefix: 'zope2.7', release: '3.1', reference: '2.7.5-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope2.7 is vulnerable in Debian sarge.\nUpgrade to zope2.7_2.7.5-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
