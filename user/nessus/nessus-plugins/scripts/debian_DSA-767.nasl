# This script was automatically generated from the dsa-767
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Marcin Slusarz discovered two integer overflow vulnerabilities in
libgadu, a library provided and used by ekg, a console Gadu Gadu
client, an instant messaging program, that could lead to the execution
of arbitrary code.
The library is also used by other packages such as kopete, which
should be restarted to take effect of this update.
The old stable distribution (woody) does not contain an ekg package.
For the stable distribution (sarge) these problems have been fixed in
version 1.5+20050411-5.
For the unstable distribution (sid) these problems have been fixed in
version 1.5+20050718+1.6rc3-1.
We recommend that you upgrade your ekg package.


Solution : http://www.debian.org/security/2005/dsa-767
Risk factor : High';

if (description) {
 script_id(19316);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "767");
 script_cve_id("CVE-2005-1852");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA767] DSA-767-1 ekg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-767-1 ekg");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'ekg', release: '', reference: '1.5+20050718+1.6rc3-1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ekg is vulnerable in Debian .\nUpgrade to ekg_1.5+20050718+1.6rc3-1\n');
}
if (deb_check(prefix: 'ekg', release: '3.1', reference: '1.5+20050411-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ekg is vulnerable in Debian 3.1.\nUpgrade to ekg_1.5+20050411-5\n');
}
if (deb_check(prefix: 'libgadu-dev', release: '3.1', reference: '1.5+20050411-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgadu-dev is vulnerable in Debian 3.1.\nUpgrade to libgadu-dev_1.5+20050411-5\n');
}
if (deb_check(prefix: 'libgadu3', release: '3.1', reference: '1.5+20050411-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libgadu3 is vulnerable in Debian 3.1.\nUpgrade to libgadu3_1.5+20050411-5\n');
}
if (deb_check(prefix: 'ekg', release: '3.1', reference: '1.5+20050411-5')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package ekg is vulnerable in Debian sarge.\nUpgrade to ekg_1.5+20050411-5\n');
}
if (w) { security_hole(port: 0, data: desc); }
