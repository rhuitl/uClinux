# This script was automatically generated from the dsa-945
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Javier Fernández-Sanguino Peña from the Debian Security Audit project
discovered that two scripts in antiword, utilities to convert Word
files to text and Postscript, create a temporary file in an insecure
fashion.
For the old stable distribution (woody) these problems have been fixed in
version 0.32-2woody0.
For the stable distribution (sarge) these problems have been fixed in
version 0.35-2sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 0.35-2.
We recommend that you upgrade your antiword package.


Solution : http://www.debian.org/security/2006/dsa-945
Risk factor : High';

if (description) {
 script_id(22811);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "945");
 script_cve_id("CVE-2005-3126");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA945] DSA-945-1 antiword");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-945-1 antiword");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'antiword', release: '', reference: '0.35-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package antiword is vulnerable in Debian .\nUpgrade to antiword_0.35-2\n');
}
if (deb_check(prefix: 'antiword', release: '3.0', reference: '0.32-2woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package antiword is vulnerable in Debian 3.0.\nUpgrade to antiword_0.32-2woody0\n');
}
if (deb_check(prefix: 'antiword', release: '3.1', reference: '0.35-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package antiword is vulnerable in Debian 3.1.\nUpgrade to antiword_0.35-2sarge1\n');
}
if (deb_check(prefix: 'antiword', release: '3.1', reference: '0.35-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package antiword is vulnerable in Debian sarge.\nUpgrade to antiword_0.35-2sarge1\n');
}
if (deb_check(prefix: 'antiword', release: '3.0', reference: '0.32-2woody0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package antiword is vulnerable in Debian woody.\nUpgrade to antiword_0.32-2woody0\n');
}
if (w) { security_hole(port: 0, data: desc); }
