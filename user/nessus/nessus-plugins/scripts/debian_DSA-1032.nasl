# This script was automatically generated from the dsa-1032
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
It was discovered that the Plone content management system lacks security
declarations for three internal classes. This allows manipulation of user
portraits by unprivileged users.
The old stable distribution (woody) doesn\'t contain Plone.
For the stable distribution (sarge) this problem has been fixed in
version 2.0.4-3sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 2.1.2-2.
We recommend that you upgrade your zope-cmfplone package.


Solution : http://www.debian.org/security/2006/dsa-1032
Risk factor : High';

if (description) {
 script_id(22574);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1032");
 script_cve_id("CVE-2006-1711");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1032] DSA-1032-1 zope-cmfplone");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1032-1 zope-cmfplone");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zope-cmfplone', release: '', reference: '2.1.2-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope-cmfplone is vulnerable in Debian .\nUpgrade to zope-cmfplone_2.1.2-2\n');
}
if (deb_check(prefix: 'plone', release: '3.1', reference: '2.0.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package plone is vulnerable in Debian 3.1.\nUpgrade to plone_2.0.4-3sarge1\n');
}
if (deb_check(prefix: 'zope-cmfplone', release: '3.1', reference: '2.0.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope-cmfplone is vulnerable in Debian 3.1.\nUpgrade to zope-cmfplone_2.0.4-3sarge1\n');
}
if (deb_check(prefix: 'zope-cmfplone', release: '3.1', reference: '2.0.4-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zope-cmfplone is vulnerable in Debian sarge.\nUpgrade to zope-cmfplone_2.0.4-3sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
