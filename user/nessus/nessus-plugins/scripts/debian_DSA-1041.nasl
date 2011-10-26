# This script was automatically generated from the dsa-1041
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Erik Sjölund discovered that abc2ps, a translator for ABC music
description files into PostScript, does not check the boundaries when
reading in ABC music files resulting in buffer overflows.
For the old stable distribution (woody) these problems have been fixed in
version 1.3.3-2woody1.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.3-3sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 1.3.3-3sarge1.
We recommend that you upgrade your abc2ps package.


Solution : http://www.debian.org/security/2006/dsa-1041
Risk factor : High';

if (description) {
 script_id(22583);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1041");
 script_cve_id("CVE-2006-1513");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1041] DSA-1041-1 abc2ps");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1041-1 abc2ps");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'abc2ps', release: '', reference: '1.3.3-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abc2ps is vulnerable in Debian .\nUpgrade to abc2ps_1.3.3-3sarge1\n');
}
if (deb_check(prefix: 'abc2ps', release: '3.0', reference: '1.3.3-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abc2ps is vulnerable in Debian 3.0.\nUpgrade to abc2ps_1.3.3-2woody1\n');
}
if (deb_check(prefix: 'abc2ps', release: '3.1', reference: '1.3.3-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abc2ps is vulnerable in Debian 3.1.\nUpgrade to abc2ps_1.3.3-3sarge1\n');
}
if (deb_check(prefix: 'abc2ps', release: '3.1', reference: '1.3.3-3sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abc2ps is vulnerable in Debian sarge.\nUpgrade to abc2ps_1.3.3-3sarge1\n');
}
if (deb_check(prefix: 'abc2ps', release: '3.0', reference: '1.3.3-2woody1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package abc2ps is vulnerable in Debian woody.\nUpgrade to abc2ps_1.3.3-2woody1\n');
}
if (w) { security_hole(port: 0, data: desc); }
