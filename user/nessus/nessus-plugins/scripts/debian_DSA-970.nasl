# This script was automatically generated from the dsa-970
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Johannes Greil of SEC Consult discovered several cross-site scripting
vulnerabilities in kronolith, the Horde calendar application.
The old stable distribution (woody) does not contain kronolith packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.1.4-2sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 2.0.6-1 of kronolith2.
We recommend that you upgrade your kronolith and kronolith2 packages.


Solution : http://www.debian.org/security/2006/dsa-970
Risk factor : High';

if (description) {
 script_id(22836);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "970");
 script_cve_id("CVE-2005-4189");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA970] DSA-970-1 kronolith");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-970-1 kronolith");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'kronolith', release: '', reference: '2.0')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kronolith is vulnerable in Debian .\nUpgrade to kronolith_2.0\n');
}
if (deb_check(prefix: 'kronolith', release: '3.1', reference: '1.1.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kronolith is vulnerable in Debian 3.1.\nUpgrade to kronolith_1.1.4-2sarge1\n');
}
if (deb_check(prefix: 'kronolith', release: '3.1', reference: '1.1.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package kronolith is vulnerable in Debian sarge.\nUpgrade to kronolith_1.1.4-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
