# This script was automatically generated from the dsa-942
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A design error has been discovered in the Albatross web application
toolkit that causes user supplied data to be used as part of template
execution and hence arbitrary code execution.
The old stable distribution (woody) does not contain albatross packages.
For the stable distribution (sarge) this problem has been fixed in
version 1.20-2.
For the unstable distribution (sid) this problem has been fixed in
version 1.33-1.
We recommend that you upgrade your albatross package.


Solution : http://www.debian.org/security/2006/dsa-942
Risk factor : High';

if (description) {
 script_id(22808);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "942");
 script_cve_id("CVE-2006-0044");
 script_bugtraq_id(16252);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA942] DSA-942-1 albatross");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-942-1 albatross");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'albatross', release: '', reference: '1.33-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package albatross is vulnerable in Debian .\nUpgrade to albatross_1.33-1\n');
}
if (deb_check(prefix: 'python-albatross', release: '3.1', reference: '1.20-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-albatross is vulnerable in Debian 3.1.\nUpgrade to python-albatross_1.20-2\n');
}
if (deb_check(prefix: 'python-albatross-common', release: '3.1', reference: '1.20-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-albatross-common is vulnerable in Debian 3.1.\nUpgrade to python-albatross-common_1.20-2\n');
}
if (deb_check(prefix: 'python-albatross-doc', release: '3.1', reference: '1.20-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python-albatross-doc is vulnerable in Debian 3.1.\nUpgrade to python-albatross-doc_1.20-2\n');
}
if (deb_check(prefix: 'python2.2-albatross', release: '3.1', reference: '1.20-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.2-albatross is vulnerable in Debian 3.1.\nUpgrade to python2.2-albatross_1.20-2\n');
}
if (deb_check(prefix: 'python2.3-albatross', release: '3.1', reference: '1.20-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package python2.3-albatross is vulnerable in Debian 3.1.\nUpgrade to python2.3-albatross_1.20-2\n');
}
if (deb_check(prefix: 'albatross', release: '3.1', reference: '1.20-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package albatross is vulnerable in Debian sarge.\nUpgrade to albatross_1.20-2\n');
}
if (w) { security_hole(port: 0, data: desc); }
