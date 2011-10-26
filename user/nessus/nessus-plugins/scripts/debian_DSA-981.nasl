# This script was automatically generated from the dsa-981
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
"felinemalice" discovered an integer overflow in BMV, a post script viewer
for SVGAlib, that may lead to the execution of arbitrary code through
specially crafted Postscript files.
For the old stable distribution (woody) this problem has been fixed in
version 1.2-14.3.
For the stable distribution (sarge) this problem has been fixed in
version 1.2-17sarge1.
For the unstable distribution (sid) this problem has been fixed in
version 1.2-18.
We recommend that you upgrade your bmv package.


Solution : http://www.debian.org/security/2006/dsa-981
Risk factor : High';

if (description) {
 script_id(22847);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "981");
 script_cve_id("CVE-2005-3278");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA981] DSA-981-1 bmv");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-981-1 bmv");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'bmv', release: '', reference: '1.2-18')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bmv is vulnerable in Debian .\nUpgrade to bmv_1.2-18\n');
}
if (deb_check(prefix: 'bmv', release: '3.0', reference: '1.2-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bmv is vulnerable in Debian 3.0.\nUpgrade to bmv_1.2-14.3\n');
}
if (deb_check(prefix: 'bmv', release: '3.1', reference: '1.2-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bmv is vulnerable in Debian 3.1.\nUpgrade to bmv_1.2-17sarge1\n');
}
if (deb_check(prefix: 'bmv', release: '3.1', reference: '1.2-17sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bmv is vulnerable in Debian sarge.\nUpgrade to bmv_1.2-17sarge1\n');
}
if (deb_check(prefix: 'bmv', release: '3.0', reference: '1.2-14.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package bmv is vulnerable in Debian woody.\nUpgrade to bmv_1.2-14.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
