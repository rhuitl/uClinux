# This script was automatically generated from the dsa-968
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that a script in noweb, a web like literate-programming
tool, creates a temporary file in an insecure fashion.
For the old stable distribution (woody) this problem has been fixed in
version 2.9a-7.4.
For the stable distribution (sarge) this problem has been fixed in
version 2.10c-3.2.
For the unstable distribution (sid) this problem has been fixed in
version 2.10c-3.2.
We recommend that you upgrade your nowebm package.


Solution : http://www.debian.org/security/2006/dsa-968
Risk factor : High';

if (description) {
 script_id(22834);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "968");
 script_cve_id("CVE-2005-3342");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA968] DSA-968-1 noweb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-968-1 noweb");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'noweb', release: '', reference: '2.10c-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package noweb is vulnerable in Debian .\nUpgrade to noweb_2.10c-3.2\n');
}
if (deb_check(prefix: 'nowebm', release: '3.0', reference: '2.9a-7.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nowebm is vulnerable in Debian 3.0.\nUpgrade to nowebm_2.9a-7.4\n');
}
if (deb_check(prefix: 'nowebm', release: '3.1', reference: '2.10c-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package nowebm is vulnerable in Debian 3.1.\nUpgrade to nowebm_2.10c-3.2\n');
}
if (deb_check(prefix: 'noweb', release: '3.1', reference: '2.10c-3.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package noweb is vulnerable in Debian sarge.\nUpgrade to noweb_2.10c-3.2\n');
}
if (deb_check(prefix: 'noweb', release: '3.0', reference: '2.9a-7.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package noweb is vulnerable in Debian woody.\nUpgrade to noweb_2.9a-7.4\n');
}
if (w) { security_hole(port: 0, data: desc); }
