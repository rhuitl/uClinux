# This script was automatically generated from the dsa-989
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Neil McBride discovered that Zoph, a web based photo management system
performs insufficient sanitising for input passed to photo searches, which
may lead to the execution of SQL commands through a SQL injection attack.
The old stable distribution (woody) does not contain zoph packages.
For the stable distribution (sarge) this problem has been fixed in
version 0.3.3-12sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 0.5-1.
We recommend that you upgrade your zoph package.


Solution : http://www.debian.org/security/2006/dsa-989
Risk factor : High';

if (description) {
 script_id(22855);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "989");
 script_cve_id("CVE-2006-0402");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA989] DSA-989-1 zoph");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-989-1 zoph");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'zoph', release: '', reference: '0.5-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zoph is vulnerable in Debian .\nUpgrade to zoph_0.5-1\n');
}
if (deb_check(prefix: 'zoph', release: '3.1', reference: '0.3.3-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zoph is vulnerable in Debian 3.1.\nUpgrade to zoph_0.3.3-12sarge1\n');
}
if (deb_check(prefix: 'zoph', release: '3.1', reference: '0.3.3-12sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package zoph is vulnerable in Debian sarge.\nUpgrade to zoph_0.3.3-12sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
