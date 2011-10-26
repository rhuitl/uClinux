# This script was automatically generated from the dsa-605
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Haris Sehic discovered several vulnerabilities in viewcvs, a utility
for viewing CVS and Subversion repositories via HTTP.  When exporting
a repository as a tar archive the hide_cvsroot and forbidden settings
were not honoured enough.
When upgrading the package for woody, please make a copy of your
/etc/viewcvs/viewcvs.conf file if you have manually edited this file.
Upon upgrade the debconf mechanism may alter it in a way so that
viewcvs doesn\'t understand it anymore.
For the stable distribution (woody) these problems have been fixed in
version 0.9.2-4woody1.
For the unstable distribution (sid) these problems have been fixed in
version 0.9.2+cvs.1.0.dev.2004.07.28-1.2.
We recommend that you upgrade your viewcvs package.


Solution : http://www.debian.org/security/2004/dsa-605
Risk factor : High';

if (description) {
 script_id(15907);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "605");
 script_cve_id("CVE-2004-0915");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA605] DSA-605-1 viewcvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-605-1 viewcvs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'viewcvs', release: '3.0', reference: '0.9.2-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package viewcvs is vulnerable in Debian 3.0.\nUpgrade to viewcvs_0.9.2-4woody1\n');
}
if (deb_check(prefix: 'viewcvs', release: '3.1', reference: '0.9.2+cvs.1.0.dev.2004.07.28-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package viewcvs is vulnerable in Debian 3.1.\nUpgrade to viewcvs_0.9.2+cvs.1.0.dev.2004.07.28-1.2\n');
}
if (deb_check(prefix: 'viewcvs', release: '3.0', reference: '0.9.2-4woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package viewcvs is vulnerable in Debian woody.\nUpgrade to viewcvs_0.9.2-4woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
